// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

struct in6_addr;

namespace service {

using IPv4int = uint32_t;

class IpAddressChecker {
public:
	virtual ~IpAddressChecker() = default;

	virtual bool isV4AddressExternal(IPv4int addr) const = 0;

	virtual bool isV6AddressExternal(const in6_addr& addr) const = 0;
};
} // namespace service
