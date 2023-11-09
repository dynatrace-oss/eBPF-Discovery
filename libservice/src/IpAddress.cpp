// SPDX-License-Identifier: GPL-2.0
#include "service/IpAddress.h"

namespace service {

std::string ipv4ToString(const IPv4bytes addr) {
	char ipAddress[INET_ADDRSTRLEN];
	const auto res{inet_ntop(AF_INET, addr, ipAddress, sizeof(ipAddress))};

	if (res == nullptr) {
		return {};
	}

	return std::string(ipAddress);
}

std::string ipv6ToString(const IPv6bytes addr) {
	char ipAddress[INET6_ADDRSTRLEN];
	const auto res{inet_ntop(AF_INET6, addr, ipAddress, sizeof(ipAddress))};

	if (res == nullptr) {
		return {};
	}

	return std::string(ipAddress);
}

} // namespace service
