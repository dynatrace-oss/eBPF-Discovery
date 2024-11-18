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

#include "service/IpAddressCheckerImpl.h"

#include "logging/Logger.h"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <ifaddrs.h>
#include <iostream>
#include <service/IpAddress.h>

namespace service {

IpAddressCheckerImpl::IpAddressCheckerImpl(InterfacesReader& interfaceReader) : interfacesReader{interfaceReader} {
	readNetworks();
}

void IpAddressCheckerImpl::readNetworks() {
	interfacesReader.collectAllIpInterfaces();
	interfacesReader.printNetworksInfo();
}

bool IpAddressCheckerImpl::isV4AddressExternal(const in_addr& addr) const {
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
		if ((ntohl(addr.s_addr) & mask) == network) {
			LOG_DEBUG("Address {} internal, belonging to reserved range (network, mask): {:#x}, {:#x}",
				ipv4InAdrToString(addr),
				network,
				mask);
			return false;
		}
	}

	for (const auto& ipv4Network : interfacesReader.getIpV4Interfaces()) {
		if (checkSubnetIpv4(addr, ipv4Network.networkIpv4Addr, ipv4Network.networkMask)) {
		LOG_DEBUG("Address {} internal, belonging to local interface (addr, mask): {}, {}",
			ipv4InAdrToString(addr),
			ipv4InAdrToString(ipv4Network.networkIpv4Addr),
			ipv4InAdrToString(ipv4Network.networkMask));
			return false;
		}
	}

	return true;
}

bool IpAddressCheckerImpl::ipv6AddressContainsMappedIpv4Address(const in6_addr& addr) const {
	for (const auto& internalRange : {"::ffff:0:0/96", "::ffff:0:0:0/96", "64:ff9b::/96"}) {
		if (isInRange(addr, internalRange)) {
			return true;
		}
	}

	return false;
}

std::optional<IPv4int> IpAddressCheckerImpl::getMappedIPv4Addr(const in6_addr& addr) const {
	if (!ipv6AddressContainsMappedIpv4Address(addr)) {
		return std::nullopt;
	}
	uint32_t ipv4Binary = (static_cast<uint32_t>(addr.s6_addr[15]) << 24) | (static_cast<uint32_t>(addr.s6_addr[14]) << 16) |
						  (static_cast<uint32_t>(addr.s6_addr[13]) << 8) | static_cast<uint32_t>(addr.s6_addr[12]);
	return ipv4Binary;
}

IpAddressCheckerImpl::ipv6Range IpAddressCheckerImpl::parseIpv6Range(const std::string& range) const {
	ipv6Range rangeStruct;
	const auto slashPos{range.find('/')};
	rangeStruct.ipv6Address = range.substr(0, slashPos);
	rangeStruct.prefixLength = slashPos != std::string::npos ? std::stoi(range.substr(slashPos + 1)) : 0;
	return rangeStruct;
}

bool IpAddressCheckerImpl::isInRange(const in6_addr& addr, const std::string& range) const {
	auto rangeStruct{IpAddressCheckerImpl::parseIpv6Range(range)};

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

bool IpAddressCheckerImpl::checkSubnet(
		const in6_addr& addrToCheck, const in6_addr& interfaceIpv6Addr, const in6_addr& interfaceMask) const {
	const auto s6Addr32ArraySize = sizeof(addrToCheck.s6_addr32) / sizeof(addrToCheck.s6_addr32[0]);
	for (size_t i = 0; i < s6Addr32ArraySize; ++i) {
		if ((addrToCheck.s6_addr32[i] & interfaceMask.s6_addr32[i]) != (interfaceIpv6Addr.s6_addr32[i] & interfaceMask.s6_addr32[i])) {
			return false;
		}
	}
	return true;
}

bool IpAddressCheckerImpl::checkSubnetIpv4(
	const in_addr& addrToCheck, const in_addr& interfaceIpv4Addr, const in_addr& interfaceMask) const {
	if ((addrToCheck.s_addr & interfaceMask.s_addr) != (interfaceIpv4Addr.s_addr & interfaceMask.s_addr)) {
		return false;
	}
	return true;
}
bool IpAddressCheckerImpl::isV6AddressExternal(const in6_addr& addr) const {
	if (auto mappedV4Addr = getMappedIPv4Addr(addr); mappedV4Addr) {
		return isV4AddressExternal(static_cast<in_addr>(*mappedV4Addr));
	}

	for (auto& ipv6Network : interfacesReader.getIpV6Interfaces()) {
		if (checkSubnet(addr, ipv6Network.networkIpv6Addr, ipv6Network.networkMask)) {
			return false;
		}
	}

	for (const auto& internalRange : {"fc00::/7", "fec0::/10", "fe80::/10", "::1/128"}) {
		if (isInRange(addr, internalRange)) {
			return false;
		}
	}

	return true;
}

} // namespace service
