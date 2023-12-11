// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "IpAddressChecker.h"
#include "NetlinkCalls.h"

namespace service {

class IpAddressNetlinkChecker : public IpAddressChecker {
public:
	explicit IpAddressNetlinkChecker(const NetlinkCalls& calls);

	bool isAddressExternalLocal(IPv4int addr) const override;
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
