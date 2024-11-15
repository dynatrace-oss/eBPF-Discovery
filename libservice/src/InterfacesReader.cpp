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

#include "service/InterfacesReader.h"

#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <ifaddrs.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "NetlinkSocket.h"
#include "logging/Logger.h"

namespace service {

void InterfacesReader::printNetworkInterfacesInfo() {
	LOG_INFO("{} network IPv4 interfaces have been discovered:", ipv4Interfaces.size());
	for (const auto& ifce : ipv4Interfaces) {
		std::string ipAddresses{boost::algorithm::join(
				ifce.networkIpv4Addr | boost::adaptors::transformed([](auto ip) {
					char buff[16];
					return std::string{inet_ntop(AF_INET, &ip, buff, sizeof(buff))};
				}),
				", ")};
	LOG_INFO("IP addresses: {}", ipAddresses);
	}
	LOG_INFO("{} IPv6 networks have been discovered:", ipv6Interfaces.size());
	for (const auto& ipv6Network : ipv6Interfaces) {
		char ipv6NetworkAddrString[INET6_ADDRSTRLEN];
		char ipv6NetworkMaskString[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &(ipv6Network.networkIpv6Addr), ipv6NetworkAddrString, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ipv6Network.networkMask), ipv6NetworkMaskString, INET6_ADDRSTRLEN);
		LOG_INFO("Detected IPv6 network: {}, Mask: {}", ipv6NetworkAddrString, ipv6NetworkMaskString);
	}
}

void InterfacesReader::collectAllIpInterfaces() {
	ifaddrs* ifAddressStruct = nullptr;
	if (getifaddrs(&ifAddressStruct) != 0) {
		LOG_WARN("Error while collecting IP interfaces, getifaddrs returned error: {}", strerror(errno));
		return;
	}
	for (const ifaddrs* ifa = ifAddressStruct; ifa != nullptr; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == nullptr) {
			continue;
		}
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			const in6_addr networkIpv6Addr = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr)->sin6_addr;
			const in6_addr networkMask = reinterpret_cast<sockaddr_in6*>(ifa->ifa_netmask)->sin6_addr;

			ipv6Interfaces.emplace_back(Ipv6Network{networkIpv6Addr, networkMask});
			continue;
		}
		if (ifa->ifa_addr->sa_family == AF_INET) {
			auto address = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr.s_addr;
			auto mask = reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask)->sin_addr.s_addr;
			std::optional<in_addr_t> broadcast{};
			if (ifa->ifa_flags & IFF_BROADCAST) {
				broadcast = std::optional<in_addr_t>(reinterpret_cast<sockaddr_in*>(ifa->ifa_ifu.ifu_broadaddr)->sin_addr.s_addr);
			}
			ipv4Interfaces.emplace_back(Ipv4Network{{address}, mask, broadcast});
		}
	}
	freeifaddrs(ifAddressStruct);
}

std::vector<Ipv4Network> InterfacesReader::getIpV4Interfaces() const {
	return ipv4Interfaces;
}

std::vector<Ipv6Network> InterfacesReader::getIpV6Interfaces() const {
	return ipv6Interfaces;
}

} // namespace service
