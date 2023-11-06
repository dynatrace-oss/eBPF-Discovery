// SPDX-License-Identifier: Apache-2.0
#include "service/NetlinkCalls.h"

#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <linux/rtnetlink.h>
#include <net/if.h>

namespace service {

static constexpr uint32_t BUFFLEN{4096};

static void addNetlinkMsg(nlmsghdr* nh, int type, const void* data, int dataLen) {
	struct rtattr* rta;
	int rta_length = RTA_LENGTH(dataLen);

	rta = reinterpret_cast<rtattr*>((char*)nh + NLMSG_ALIGN(nh->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = rta_length;
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta_length);

	memcpy(RTA_DATA(rta), data, dataLen);
}

int NetlinkCalls::sendIpAddrRequest(int fd, sockaddr_nl* dst, int domain) const {
	std::array<char, BUFFLEN> buf{};

	nlmsghdr* nl;
	nl = reinterpret_cast<nlmsghdr*>(buf.data());
	nl->nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
	nl->nlmsg_type = RTM_GETADDR;
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

	ifaddrmsg* ifa;
	ifa = reinterpret_cast<ifaddrmsg*>(NLMSG_DATA(nl));
	ifa->ifa_family = domain; // ipv4 or ipv6

	iovec iov = {nl, nl->nlmsg_len};
	msghdr msg = {dst, sizeof(*dst), &iov, 1, NULL, 0, 0};

	return sendmsg(fd, &msg, 0);
}

int NetlinkCalls::sendBridgesRequest(int fd, sockaddr_nl* dst, int domain) const {
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char _[1024]; // space for rtattr array
	} r{};

	const char* dev_type = "bridge";

	r.n.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
	r.n.nlmsg_type = RTM_GETLINK;
	r.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	r.i.ifi_family = AF_PACKET;
	r.n.nlmsg_pid = 0;
	r.n.nlmsg_seq = 0;

	rtattr* linkinfo = reinterpret_cast<rtattr*>((char*)&r.n + NLMSG_ALIGN(r.n.nlmsg_len));
	addNetlinkMsg(&r.n, IFLA_LINKINFO, NULL, 0);
	addNetlinkMsg(&r.n, IFLA_INFO_KIND, dev_type, strlen(dev_type) + 1);
	linkinfo->rta_len = (int)(reinterpret_cast<char*>(&r.n) + NLMSG_ALIGN(r.n.nlmsg_len) - reinterpret_cast<char*>(linkinfo));

	iovec iov = {&r.n, r.n.nlmsg_len};
	msghdr msg = {dst, sizeof(*dst), &iov, 1, NULL, 0, 0};

	return sendmsg(fd, &msg, 0);
}

int NetlinkCalls::receive(int fd, sockaddr_nl* dst, void* buf, size_t len) const {
	iovec iov;
	msghdr msg{};
	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_name = dst;
	msg.msg_namelen = sizeof(*dst);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return recvmsg(fd, &msg, 0);
}
} // namespace service
