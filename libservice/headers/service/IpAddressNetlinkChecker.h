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

#include "IpAddressChecker.h"
#include "NetlinkCalls.h"

namespace service {

class IpAddressNetlinkChecker : public IpAddressChecker {
public:
	explicit IpAddressNetlinkChecker(const NetlinkCalls& calls);

	bool isV4AddressExternal(IPv4int addr) const override;

	bool isV6AddressExternal(const in6_addr& addr) const override;

private:
	void readNetworks();

	void printNetworkInterfacesInfo();

	bool isLocalBridge(int index) const {
		if (const auto it{isLocalBridgeMap.find(index)}; it != isLocalBridgeMap.end()) {
			return it->second;
		}

		return false;
	}

	const NetlinkCalls& netlink;
	IpInterfaces ipInterfaces;
	std::unordered_map<int, bool> isLocalBridgeMap;
};
} // namespace service
