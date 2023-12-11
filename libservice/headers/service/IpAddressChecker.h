// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

namespace service {

using IPv4int = uint32_t;

class IpAddressChecker {
public:
	virtual ~IpAddressChecker() = default;

	virtual bool isAddressExternalLocal(IPv4int addr) const = 0;

};
} // namespace service
