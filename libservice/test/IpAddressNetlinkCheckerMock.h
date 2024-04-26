/*
 * Copyright 2024 Dynatrace LLC
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

#include <gmock/gmock.h>

#include "service/IpAddressNetlinkChecker.h"

namespace service {

class IpAddressNetlinkCheckerMock : public IpAddressNetlinkChecker {
public:
	explicit IpAddressNetlinkCheckerMock(const NetlinkCalls& calls) : IpAddressNetlinkChecker(calls) {};

	MOCK_CONST_METHOD0(getIpv6Interfaces, std::vector<Ipv6Interface>());
};

} // namespace service
