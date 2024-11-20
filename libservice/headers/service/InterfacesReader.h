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

#pragma once

#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <stddef.h>
#include <unordered_map>
#include <vector>

struct sockaddr_nl;

namespace service {

struct Ipv6Network {
		in6_addr networkIpv6Addr;
		in6_addr networkMask;
};

struct Ipv4Network {
		in_addr networkIpv4Addr;
		in_addr networkMask;
		std::optional<in_addr> broadcastAddr;
};


class InterfacesReader {
public:
	virtual ~InterfacesReader() = default;
	void printNetworksInfo();
	[[nodiscard]] virtual std::vector<Ipv4Network> getIpV4Interfaces() const;
	[[nodiscard]] virtual std::vector<Ipv6Network> getIpV6Interfaces() const;

	virtual void collectAllIpInterfaces();

private:
	std::vector<Ipv4Network> ipv4Networks;
	std::vector<Ipv6Network> ipv6Networks;

};

} // namespace service
