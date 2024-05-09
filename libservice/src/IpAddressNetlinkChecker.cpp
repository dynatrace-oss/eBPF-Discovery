/*
 * Copyright 2023 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "service/IpAddressNetlinkChecker.h"

#include "logging/Logger.h"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <iostream>
#include <ifaddrs.h>

namespace service {

IpAddressNetlinkChecker::IpAddressNetlinkChecker(const NetlinkCalls& calls) : netlink{calls} {
	readNetworks();
}

void IpAddressNetlinkChecker::readNetworks() {
	ipInterfaces = netlink.collectIpInterfaces();

	for (const auto& [index, ipIfce] : ipInterfaces) {
		isLocalBridgeMap[index] = false;
	}

	for (const auto& index : netlink.collectBridgeIndices()) {
		isLocalBridgeMap[index] = true;
	}

	printNetworkInterfacesInfo();
}

void IpAddressNetlinkChecker::printNetworkInterfacesInfo() {
	LOG_INFO("{} network interfaces have been discovered:", ipInterfaces.size());
	for (const auto& [index, ifce] : ipInterfaces) {
		std::string ipAddresses{boost::algorithm::join(
				ifce.ip | boost::adaptors::transformed([](auto ip) {
					char buff[16];
					return std::string{inet_ntop(AF_INET, &ip, buff, sizeof(buff))};
				}),
				", ")};
		LOG_INFO("index: {}, IP addresses: {}{}", index, ipAddresses, isLocalBridge(index) ? " (local bridge)" : "");
	}
}

bool IpAddressNetlinkChecker::isV4AddressExternal(IPv4int addr) const {
	// Special-Purpose IP Address Registries (https://datatracker.ietf.org/doc/html/rfc6890)
	static const struct {
		uint32_t network;
		uint32_t mask;
	} reservedRanges[] = {
			{0x00000000, 0xff000000}, // 0.0.0.0/8
			{0x0a000000, 0xff000000}, // 10.0.0.0/8
			{0x64400000, 0xffc00000}, // 100.64.0.0/10
			{0x7f000000, 0xff000000}, // 127.0.0.0/8
			{0xa9fe0000, 0xffff0000}, // 169.254.0.0/16
			{0xac100000, 0xfff00000}, // 172.16.0.0/12
			{0xc0000000, 0xffffff00}, // 192.0.0.0/24
			{0xc0000200, 0xffffff00}, // 192.0.2.0/24
			{0xc0586300, 0xffffff00}, // 192.88.99.0/24
			{0xc0a80000, 0xffff0000}, // 192.168.0.0/16
			{0xc6120000, 0xfffE0000}, // 198.18.0.0/15
			{0xc6336400, 0xffffff00}, // 198.51.100.0/24
			{0xcb007100, 0xffffff00}, // 203.0.113.0/24
			{0xe0000000, 0xf0000000}, // 224.0.0.0/4
			{0xe9fc0000, 0xffff0000}, // 233.252.0.0/24
			{0xf0000000, 0xf0000000}, // 240.0.0.0/4
			{0xffffffff, 0xffffffff}  // 255.255.255.255/32
	};

	for (const auto& [network, mask] : reservedRanges) {
		if ((htonl(addr) & mask) == network) {
			return false;
		}
	}

	const bool srcLocal{std::any_of(ipInterfaces.begin(), ipInterfaces.end(), [addr, this](const auto& ipInterfaceEntry) {
		const auto& [ipInterfaceIndex, ipInterface]{ipInterfaceEntry};
		return std::any_of(ipInterface.ip.begin(), ipInterface.ip.end(), [addr, index = ipInterfaceIndex, this](const auto& ip) {
			return !isLocalBridge(index) && addr == ip;
		});
	})};

	if (srcLocal) {
		return false;
	}

	const bool bridgeRelated{std::any_of(ipInterfaces.begin(), ipInterfaces.end(), [addr, this](const auto& ipInterfaceEntry) {
		const auto& [ipInterfaceIndex, ipInterface]{ipInterfaceEntry};
		return std::any_of(
				ipInterface.ip.begin(),
				ipInterface.ip.end(),
				[addr, index = ipInterfaceIndex, mask = ipInterface.mask, this](const auto& ip) {
					return isLocalBridge(index) && (addr & mask) == (ip & mask);
				});
	})};

	if (bridgeRelated) {
		return false;
	}

	return true;
}

bool IpAddressNetlinkChecker::ipv6AddressContainsMappedIpv4Address(const in6_addr& addr) const {
	for (const auto& internalRange : {"::ffff:0:0:0/96", "64:ff9b::/96"}) {
		if (isInRange(addr, internalRange)) {
			return true;
		}
	}

	if (!std::all_of(addr.s6_addr, addr.s6_addr + 9, [](auto byte) { return byte == 0; })) {
		return false;
	}

	return (addr.s6_addr[10] == 0xFF && addr.s6_addr[11] == 0xFF);
}

std::optional<IPv4int> IpAddressNetlinkChecker::getMappedIPv4Addr(const in6_addr& addr) const {
	if (!ipv6AddressContainsMappedIpv4Address(addr)) {
		return std::nullopt;
	}
	uint32_t ipv4Binary = (static_cast<uint32_t>(addr.s6_addr[15]) << 24) | (static_cast<uint32_t>(addr.s6_addr[14]) << 16) |
						  (static_cast<uint32_t>(addr.s6_addr[13]) << 8) | static_cast<uint32_t>(addr.s6_addr[12]);
	return ipv4Binary;
}

IpAddressNetlinkChecker::ipv6Range IpAddressNetlinkChecker::parseIpv6Range(const std::string& range) const {
	ipv6Range rangeStruct;
	const auto slashPos{range.find('/')};
	rangeStruct.ipv6Address = range.substr(0, slashPos);
	rangeStruct.prefixLength = slashPos != std::string::npos ? std::stoi(range.substr(slashPos + 1)) : 0;
	return rangeStruct;
}

bool IpAddressNetlinkChecker::isInRange(const in6_addr& addr, const std::string& range) const {
	auto rangeStruct{IpAddressNetlinkChecker::parseIpv6Range(range)};

	in6_addr rangeIpv6Address{};
	inet_pton(AF_INET6, rangeStruct.ipv6Address.c_str(), &rangeIpv6Address);

	// Create mask
	in6_addr mask{};
	for (size_t i = 0; i < sizeof(mask.s6_addr); i++) {
		if (rangeStruct.prefixLength >= 8) {
			mask.s6_addr[i] = 0xFF;
			rangeStruct.prefixLength -= 8;
		} else if (rangeStruct.prefixLength > 0) {
			mask.s6_addr[i] = (uint8_t)(0xFF << (8 - rangeStruct.prefixLength));
			rangeStruct.prefixLength = 0;
		} else {
			mask.s6_addr[i] = 0;
		}
	}

	// Check mask and addr
	in6_addr andResult{};
	for (size_t i = 0; i < sizeof(andResult.s6_addr); ++i) {
		andResult.s6_addr[i] = addr.s6_addr[i] & mask.s6_addr[i];
	}

	// Compare andResult with IPv6 address of the rangeStruct
	return memcmp(&andResult, &rangeIpv6Address, sizeof(andResult)) == 0;
}

bool IpAddressNetlinkChecker::checkSubnet(
		const in6_addr& addrToCheck, const in6_addr& interfaceIpv6Addr, const in6_addr& interfaceMask) const {
	const auto s6Addr32ArraySize = sizeof(addrToCheck.s6_addr32) / sizeof(addrToCheck.s6_addr32[0]);
	for (size_t i = 0; i < s6Addr32ArraySize; ++i) {
		if ((addrToCheck.s6_addr32[i] & interfaceMask.s6_addr32[i]) != (interfaceIpv6Addr.s6_addr32[i] & interfaceMask.s6_addr32[i])) {
			return false;
		}
	}
	return true;
}

bool IpAddressNetlinkChecker::isV6AddressExternal(const in6_addr& addr) const {
	if (auto mappedV4Addr = getMappedIPv4Addr(addr); mappedV4Addr) {
		return isV4AddressExternal(*mappedV4Addr);
	}

	for (auto& ipv6Interface : netlink.collectIpv6Interfaces()) {
		if (checkSubnet(addr, ipv6Interface.interfaceIpv6Addr, ipv6Interface.interfaceMask)) {
			return false;
		}
	}

	for (const auto& internalRange : {"fc00::/7", "fec0::/10", "fe80::/10", "::1/128"}) {
		if (IpAddressNetlinkChecker::isInRange(addr, internalRange)) {
			return false;
		}
	}

	return true;
}

} // namespace service
