// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <memory>
#include <stddef.h>
#include <unordered_map>
#include <vector>

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

	virtual IpInterfaces collectIpInterfaces() const;
	virtual BridgeIndices collectBridgeIndices() const;
};

} // namespace service
