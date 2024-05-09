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
#include <stddef.h>
#include <unordered_map>
#include <vector>
#include <netinet/in.h>

struct sockaddr_nl;

namespace service {

using IPv4int = uint32_t;

struct IpIfce {
	std::vector<IPv4int> ip;
	std::vector<IPv4int> broadcast;
	uint32_t mask;
};

using IpInterfaces = std::unordered_map<int, IpIfce>;
using BridgeIndices = std::vector<int>;

class NetlinkCalls {
public:
	virtual ~NetlinkCalls() = default;

	struct Ipv6Interface {
		in6_addr interfaceIpv6Addr;
		in6_addr interfaceMask;
	};

	virtual IpInterfaces collectIpInterfaces() const;
	virtual std::vector<Ipv6Interface> collectIpv6Interfaces() const;
	virtual BridgeIndices collectBridgeIndices() const;
};

} // namespace service
