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
