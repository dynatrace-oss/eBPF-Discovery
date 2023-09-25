// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdint>
#include <vector>

namespace ebpfdiscovery {

using IPv4 = uint32_t;

struct IpIfce {
	std::vector<IPv4> ip;
	std::vector<IPv4> broadcast;
	uint32_t mask;
	int index;
	bool isLocalBridge;
};

class IpAddressChecker {
protected:
	std::vector<IpIfce> localNetsIpv4;
	std::vector<IpIfce>::iterator bridgeEnd = localNetsIpv4.end();
	bool readAllIpAddrs();
	bool markLocalBridges();
	std::vector<IpIfce>::iterator moveBridges();

public:
	IpAddressChecker() = default;
	bool isAddressExternalLocal(IPv4 addr);
	void addIpIfce(IpIfce&& ifce);
	void markBridge(int idx);
	bool readNetworks();
};
}

