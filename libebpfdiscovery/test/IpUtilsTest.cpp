#include "ebpfdiscovery/IpUtils.h"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <initializer_list>

using namespace ebpfdiscovery;

class IpUtilsTest : public IpUtils {
protected:
public:
	using IpUtils::IpUtils;
	void addIfceConfig(std::initializer_list<IpIfce> config) {
		localNetsIpv4.insert(localNetsIpv4.end(), config.begin(), config.end());
		bridgeEnd = moveBridges();
	}
};


TEST(IpUtils, LocalBridgeIp) {
	IpUtilsTest u;
	u.addIfceConfig({{{inet_addr("10.2.4.5")}, {}, 0x0000ffff, 0, true}, {{inet_addr("10.7.4.5")}, {}, 0x0000ffff, 0, false}});
	u.printAll();
	EXPECT_FALSE(u.isAddresExternalLocal(inet_addr("10.2.6.5")));
}

TEST(IpUtils, NOTLocalBridgeIp) {
	IpUtilsTest u;
	u.addIfceConfig({{{inet_addr("10.2.6.5")}, {}, 0x0000ffff, 0, true}});
	EXPECT_TRUE(u.isAddresExternalLocal(inet_addr("10.3.34.2")));
}

TEST(IpUtils, SimpleClassATest) {
	IpUtilsTest u;
	EXPECT_TRUE(u.isAddresExternalLocal(inet_addr("192.168.1.2")));
}

TEST(IpUtils, SimpleClassBTest) {
	IpUtilsTest u;
	EXPECT_TRUE(u.isAddresExternalLocal(inet_addr("172.20.21.2")));
}

TEST(IpUtils, SimpleClassCtest) {
	IpUtilsTest u;
	EXPECT_TRUE(u.isAddresExternalLocal(inet_addr("10.2.4.5")));
}

TEST(IpUtils, SimpleLinkLocal) {
	IpUtilsTest u;
	EXPECT_FALSE(u.isAddresExternalLocal(inet_addr("169.254.76.6")));
}


TEST(IpUtils, SimplePublicIp) {
	IpUtilsTest u;
	EXPECT_FALSE(u.isAddresExternalLocal(inet_addr("170.254.76.6")));
}
