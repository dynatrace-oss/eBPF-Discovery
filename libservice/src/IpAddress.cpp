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

std::string ipv4InAdrToString(const in_addr& addr) {
	return ipv4ToString(reinterpret_cast<const IPv4bytes&>(addr));
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
