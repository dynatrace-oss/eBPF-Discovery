// SPDX-License-Identifier: Apache-2.0
#include "StringFunctions.h"

#include <arpa/inet.h>

namespace ebpfdiscovery {

std::string ipv4ToString(const uint8_t ip[4]) {
	char ipAddress[INET_ADDRSTRLEN];
	const auto res{inet_ntop(AF_INET, ip, ipAddress, sizeof(ipAddress))};

	if (res == nullptr) {
		return {};
	}

	return std::string(ipAddress);
}

std::string ipv6ToString(const uint8_t ip[16]) {
	char ipAddress[INET6_ADDRSTRLEN];
	const auto res{inet_ntop(AF_INET6, ip, ipAddress, sizeof(ipAddress))};

	if (res == nullptr) {
		return {};
	}

	return std::string(ipAddress);
}

} // namespace ebpfdiscovery
