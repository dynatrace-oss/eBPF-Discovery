// SPDX-License-Identifier: Apache-2.0
#include "service/IpAddressNetlinkChecker.h"

#include "logging/Logger.h"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>

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

static bool isIPv4MappedIPv6(const in6_addr& addr) {
	if (!std::all_of(addr.s6_addr, addr.s6_addr + 9, [](auto byte) { return byte == 0; })) {
		return false;
	}
	return (addr.s6_addr[10] == 0xFF && addr.s6_addr[11] == 0xFF);
}

static std::optional<IPv4int> getMappedIPv4Addr(const in6_addr& addr) {
	if (!isIPv4MappedIPv6(addr)) {
		return std::nullopt;
	}
	std::string ipv4String{fmt::format("{}.{}.{}.{}", addr.s6_addr[12], addr.s6_addr[13], addr.s6_addr[14], addr.s6_addr[15])};
	IPv4int ipv4Binary;
	if (inet_pton(AF_INET, ipv4String.c_str(), &ipv4Binary) != 1) {
		throw std::runtime_error("Invalid IPv4 address: " + ipv4String);
	}
	return ipv4Binary;
}

bool IpAddressNetlinkChecker::isV6AddressExternal(const in6_addr& addr) const {
	if (auto mappedV4Addr = getMappedIPv4Addr(addr); mappedV4Addr) {
		return isV4AddressExternal(*mappedV4Addr);
	} else {
		throw std::runtime_error("IPv6 only supported for IPv4 mapped addresses");
	}
}

} // namespace service
