// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "ebpfdiscovery/NetlinkCalls.h"
#include <initializer_list>
#include <vector>


namespace ebpfdiscovery {

using IPv4int = uint32_t;

struct IpIfce {
	std::vector<IPv4int> ip;
	std::vector<IPv4int> broadcast;
	uint32_t mask;
	int index;
	bool isLocalBridge;
};

class IpAddressChecker {
	std::vector<IpIfce> interfaces;
	std::vector<IpIfce>::iterator bridgeEnd = interfaces.end();
	const NetlinkCalls& netlink;

	bool readAllIpAddrs();
	bool markLocalBridges();
	bool isLoopback(const IpIfce&);
	void addIpIfce(IpIfce&& ifce);
	void markBridge(int idx);
protected:
	void moveBridges();
public:
	IpAddressChecker(const NetlinkCalls &calls);
	IpAddressChecker(std::initializer_list<IpIfce> config, const NetlinkCalls &calls);
	bool isAddressExternalLocal(IPv4int addr);
	bool readNetworks();
};
} // namespace ebpfdiscovery

