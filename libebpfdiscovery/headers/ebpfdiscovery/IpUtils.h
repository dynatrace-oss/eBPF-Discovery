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

class IpUtils {
protected:
	std::vector<IpIfce> localNetsIpv4;
	std::vector<IpIfce>::iterator bridgeEnd = localNetsIpv4.end();
	bool readAllIpAddrs();
	bool markLocalBridges();
	std::vector<IpIfce>::iterator moveBridges();

public:
	IpUtils() = default;
	bool isAddresExternalLocal(IPv4 addr);
	void addIpIfce(IpIfce&& ifce);
	void markBridge(int idx);
	void printAll();
	bool readNetworks();
};
}

