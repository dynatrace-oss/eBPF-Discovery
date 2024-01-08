// SPDX-License-Identifier: Apache-2.0
#include "NetlinkCallsMock.h"
#include "service/IpAddressNetlinkChecker.h"

#include <arpa/inet.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace service;
using namespace ::testing;

class IpAddressCheckerTest : public Test {
public:
	NiceMock<NetlinkCallsMock> netlinkMock;
};

// 0.0.0.0/8
TEST_F(IpAddressCheckerTest, Test0_0_0_0_8) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("0.0.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("0.255.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("0.54.189.245")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("0.128.0.1")));
}

// 10.0.0.0/8
TEST_F(IpAddressCheckerTest, Test10_0_0_0_8) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("10.0.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("10.255.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("10.54.189.245")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("10.128.0.1")));
}

// 100.64.0.0/10
TEST_F(IpAddressCheckerTest, Test100_64_0_0_10) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("100.64.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("100.127.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("100.64.128.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("100.66.0.1")));
}

// 127.0.0.0/8
TEST_F(IpAddressCheckerTest, Test127_0_0_0_8) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("127.0.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("127.255.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("127.0.0.1")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("127.128.0.1")));
}

// 169.254.0.0/16
TEST_F(IpAddressCheckerTest, Test169_254_0_0_16) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("169.254.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("169.254.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("169.254.128.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("169.254.192.1")));
}

// 172.16.0.0/12
TEST_F(IpAddressCheckerTest, Test172_16_0_0_12) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("172.16.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("172.31.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("172.20.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("172.24.0.1")));
}

// 192.0.0.0/24
TEST_F(IpAddressCheckerTest, Test192_0_0_0_24) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.0.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.0.0.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.0.0.128")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.0.0.1")));
}

// 192.0.2.0/24
TEST_F(IpAddressCheckerTest, Test192_0_2_0_24) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.0.2.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.0.2.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.0.2.128")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.0.2.1")));
}

// 192.88.99.0/24
TEST_F(IpAddressCheckerTest, Test192_88_99_0_24) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.88.99.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.88.99.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.88.99.128")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.88.99.1")));
}

// 192.168.0.0/
TEST_F(IpAddressCheckerTest, Test192_168_0_0_16) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.168.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.168.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.168.128.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("192.168.192.1")));
}

// 198.18.0.0/15
TEST_F(IpAddressCheckerTest, Test198_18_0_0_15) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("198.18.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("198.19.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("198.18.128.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("198.18.192.1")));
}

// 198.51.100.0/24
TEST_F(IpAddressCheckerTest, Test198_51_100_0_24) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("198.51.100.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("198.51.100.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("198.51.100.128")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("198.51.100.1")));
}

// 203.0.113.0/24
TEST_F(IpAddressCheckerTest, Test203_0_113_0_24) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("203.0.113.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("203.0.113.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("203.0.113.128")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("203.0.113.1")));
}

// 224.0.0.0/4
TEST_F(IpAddressCheckerTest, Test224_0_0_0_4) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("224.0.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("239.255.255.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("225.128.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("230.0.0.1")));
}

// 233.252.0.0/24
TEST_F(IpAddressCheckerTest, Test233_252_0_0_24) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("233.252.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("233.252.0.255")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("233.252.0.128")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("233.252.0.1")));
}

// 240.0.0.0/4
TEST_F(IpAddressCheckerTest, Test240_0_0_0_4) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// Range boundaries
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("240.0.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("255.255.255.254")));

	// Middle of the range
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("241.128.0.0")));
	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("248.0.0.1")));
}

// 255.255.255.255/32
TEST_F(IpAddressCheckerTest, Test255_255_255_255_32) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("255.255.255.255")));
}

TEST_F(IpAddressCheckerTest, LocalBridgeIp) {
	EXPECT_CALL(netlinkMock, collectIpInterfaces).WillOnce(Return(IpInterfaces{{0, IpIfce{{inet_addr("142.15.4.0")}, {}, 0x0000ffff}}}));
	EXPECT_CALL(netlinkMock, collectBridgeIndices).WillOnce(Return(BridgeIndices{0}));

	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("142.15.6.5")));
}

TEST_F(IpAddressCheckerTest, LocalIfceIpSrc) {
	EXPECT_CALL(netlinkMock, collectIpInterfaces)
			.WillOnce(Return(IpInterfaces{
					{0, IpIfce{{inet_addr("115.89.3.7")}, {}, 0x0000ffff}},
			}));
	EXPECT_CALL(netlinkMock, collectBridgeIndices).WillOnce(Return(BridgeIndices{}));

	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	EXPECT_FALSE(ipAddressNetlinkChecker.isV4AddressExternal(inet_addr("115.89.3.7")));
}

static in6_addr getV6AddrBinary(std::string addr) {
	in6_addr clientAddrBinary{};
	inet_pton(AF_INET6, addr.c_str(), &clientAddrBinary);
	return clientAddrBinary;
}

// IPv4 mapped to IPv6
TEST_F(IpAddressCheckerTest, TestMapped) {
	IpAddressNetlinkChecker ipAddressNetlinkChecker{netlinkMock};

	// mapped IPv4
	EXPECT_FALSE(ipAddressNetlinkChecker.isV6AddressExternal(getV6AddrBinary("::FFFF:192.168.1.1")));

	// regular IPv6 addr
	EXPECT_THROW(
			ipAddressNetlinkChecker.isV6AddressExternal(getV6AddrBinary("2001:0db8:85a3:0000:0000:8a2e:0370:7334")), std::runtime_error);
}