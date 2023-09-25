// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/IpAddressChecker.h"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <initializer_list>

using namespace ebpfdiscovery;

class IpAddressCheckerTest : public IpAddressChecker {
protected:
public:
	using IpAddressChecker::IpAddressChecker;
	void addIfceConfig(std::initializer_list<IpIfce> config) {
		localNetsIpv4.insert(localNetsIpv4.end(), config.begin(), config.end());
		bridgeEnd = moveBridges();
	}
};

TEST(IpUtils, LocalBridgeIp) {
	IpAddressCheckerTest u;
	u.addIfceConfig({{{inet_addr("10.2.4.5")}, {}, 0x0000ffff, 0, true}, {{inet_addr("10.7.4.5")}, {}, 0x0000ffff, 0, false}});
	EXPECT_FALSE(u.isAddressExternalLocal(inet_addr("10.2.6.5")));
}

TEST(IpUtils, NOTLocalBridgeIp) {
	IpAddressCheckerTest u;
	u.addIfceConfig({{{inet_addr("10.2.6.5")}, {}, 0x0000ffff, 0, true}});
	EXPECT_TRUE(u.isAddressExternalLocal(inet_addr("10.3.34.2")));
}

TEST(IpUtils, SimpleClassATest) {
	IpAddressCheckerTest u;
	EXPECT_TRUE(u.isAddressExternalLocal(inet_addr("192.168.1.2")));
}

TEST(IpUtils, SimpleClassBTest) {
	IpAddressCheckerTest u;
	EXPECT_TRUE(u.isAddressExternalLocal(inet_addr("172.20.21.2")));
}

TEST(IpUtils, SimpleClassCtest) {
	IpAddressCheckerTest u;
	EXPECT_TRUE(u.isAddressExternalLocal(inet_addr("10.2.4.5")));
}

TEST(IpUtils, SimpleLinkLocal) {
	IpAddressCheckerTest u;
	EXPECT_FALSE(u.isAddressExternalLocal(inet_addr("169.254.76.6")));
}


TEST(IpUtils, SimplePublicIp) {
	IpAddressCheckerTest u;
	EXPECT_FALSE(u.isAddressExternalLocal(inet_addr("170.254.76.6")));
}
