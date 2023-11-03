// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/IpAddressChecker.h"
#include <arpa/inet.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace ebpfdiscovery;
using namespace ::testing;

class NetlinkCallsMock : public NetlinkCalls {
public:
	MOCK_METHOD(int, sendIpAddrRequest, (int fd, sockaddr_nl* dst, int domain), (const, override));
	MOCK_METHOD(int, sendBridgesRequest, (int fd, sockaddr_nl* dst, int domain), (const, override));
	MOCK_METHOD(int, receive, (int fd, sockaddr_nl* dst, void* buf, size_t len), (const, override));
};

class IpAddressCheckerTest : public IpAddressChecker {
protected:
public:
	using IpAddressChecker::IpAddressChecker;
	IpAddressCheckerTest(std::initializer_list<IpIfce> config, const NetlinkCallsMock& mc) : IpAddressChecker(config, mc) {
		moveBridges();
	}
};

TEST(TestAddressChecker, LocalBridgeIp) {
	const NetlinkCallsMock netlinkMock;
	IpAddressCheckerTest u(
			{{{inet_addr("10.2.4.5")}, {}, 0x0000ffff, 0, true}, {{inet_addr("10.7.4.5")}, {}, 0x0000ffff, 0, false}}, netlinkMock);
	EXPECT_FALSE(u.isAddressExternalLocal(inet_addr("10.2.6.5")));
}

TEST(TestAddressChecker, NoReadIfSendFailed) {
	const NetlinkCallsMock netlinkMock;
	EXPECT_CALL(netlinkMock, sendIpAddrRequest).WillOnce(Return(-1));
	EXPECT_CALL(netlinkMock, sendBridgesRequest).WillOnce(Return(-1));
	IpAddressCheckerTest u({}, netlinkMock);
	u.readNetworks();
}

TEST(TestAddressChecker, ReadAfterSuccessfullSend) {
	const NetlinkCallsMock netlinkMock;
	EXPECT_CALL(netlinkMock, sendIpAddrRequest).WillOnce(Return(1));
	EXPECT_CALL(netlinkMock, sendBridgesRequest).WillOnce(Return(1));
	EXPECT_CALL(netlinkMock, receive).Times(2).WillRepeatedly(Return(0));
	IpAddressCheckerTest u({}, netlinkMock);
	u.readNetworks();
}

TEST(TestAddressChecker, ReadUntilGreaterThan0) {
	const NetlinkCallsMock netlinkMock;
	EXPECT_CALL(netlinkMock, sendIpAddrRequest).WillOnce(Return(1));
	EXPECT_CALL(netlinkMock, sendBridgesRequest).WillOnce(Return(1));
	EXPECT_CALL(netlinkMock, receive).WillOnce(Return(1)).WillOnce(Return(0)).WillOnce(Return(1)).WillOnce(Return(0));
	IpAddressCheckerTest u({}, netlinkMock);
	u.readNetworks();
}

TEST(TestAddressChecker, NOTLocalBridgeIp) {
	const NetlinkCallsMock netlinkMock;
	IpAddressCheckerTest u({{{inet_addr("10.2.6.5")}, {}, 0x0000ffff, 0, true}}, netlinkMock);
	EXPECT_TRUE(u.isAddressExternalLocal(inet_addr("10.3.34.2")));
}

TEST(TestAddressChecker, LocalIfceIpSrc) {
	const NetlinkCallsMock netlinkMock;
	IpAddressCheckerTest u({{{inet_addr("10.2.6.5")}, {}, 0x0000ffff, 0, false}}, netlinkMock);
	EXPECT_FALSE(u.isAddressExternalLocal(inet_addr("10.2.6.5")));
}

TEST(TestAddressChecker, SimpleClassATest) {
	NetlinkCalls calls;
	IpAddressCheckerTest u(calls);
	EXPECT_TRUE(u.isAddressExternalLocal(inet_addr("192.168.1.2")));
}

TEST(TestAddressChecker, SimpleClassBTest) {
	NetlinkCalls calls;
	IpAddressCheckerTest u(calls);
	EXPECT_TRUE(u.isAddressExternalLocal(inet_addr("172.20.21.2")));
}

TEST(TestAddressChecker, SimpleClassCtest) {
	NetlinkCalls calls;
	IpAddressCheckerTest u(calls);
	EXPECT_TRUE(u.isAddressExternalLocal(inet_addr("10.2.4.5")));
}

TEST(TestAddressChecker, SimpleLinkLocal) {
	NetlinkCalls calls;
	IpAddressCheckerTest u(calls);
	EXPECT_FALSE(u.isAddressExternalLocal(inet_addr("169.254.76.6")));
}

TEST(TestAddressChecker, SimplePublicIp) {
	NetlinkCalls calls;
	IpAddressCheckerTest u(calls);
	EXPECT_FALSE(u.isAddressExternalLocal(inet_addr("170.254.76.6")));
}
