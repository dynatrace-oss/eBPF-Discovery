#include "ebpfdiscovery/IpUtils.h"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <errno.h>
#include <gsl/gsl_util>
#include <iostream>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string>
#include <string_view>
#include <unistd.h>

static constexpr uint32_t BUFLEN = 4096;
static constexpr uint32_t ipC = 0x0000a8c0; // 192.168.*.*
static constexpr uint32_t maskC = 0x0000ffff;
static constexpr uint32_t ipB = 0x000010ac; // 172.16-31.*.*
static constexpr uint32_t maskB = 0x0000f0ff;
static constexpr uint32_t ipA = 0x0000000a; // 10.*.*.*
static constexpr uint32_t maskA = 0x000000ff;

static void logError(std::string_view prefix) {
	std::cout << prefix << ": " << strerror(errno) << "\n";
}

static int getIp(int fd, sockaddr_nl* sa, int domain) {
	std::array<char, BUFLEN> buf{};

	nlmsghdr* nl;
	nl = (nlmsghdr*) buf.data();
	nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nl->nlmsg_type = RTM_GETADDR;
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

	ifaddrmsg* ifa;
	ifa = (ifaddrmsg*)NLMSG_DATA(nl);
	ifa->ifa_family = domain; // ipv4 or ipv6

	iovec iov = {nl, nl->nlmsg_len};
	msghdr msg = {sa, sizeof(*sa), &iov, 1, NULL, 0, 0};

	return sendmsg(fd, &msg, 0);
}

static void addNetlinkMsg(nlmsghdr* nh, int type, const void* data, int raw_data_length) {
	struct rtattr* rta;
	int rta_length = RTA_LENGTH(raw_data_length);

	rta = (rtattr*)((char*)nh + NLMSG_ALIGN(nh->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = rta_length;
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta_length);

	memcpy(RTA_DATA(rta), data, raw_data_length);
}

static int getBridges(int fd, sockaddr_nl* sa, int domain) {
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char _[1024]; // required
	} r{};

	const char* dev_type = "bridge";

	r.n.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
	r.n.nlmsg_type = RTM_GETLINK;
	r.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	r.i.ifi_family = AF_PACKET;
	r.n.nlmsg_pid = 0;
	r.n.nlmsg_seq = 0;

	rtattr* linkinfo = (rtattr*)((char*)&r.n + NLMSG_ALIGN(r.n.nlmsg_len));
	addNetlinkMsg(&r.n, IFLA_LINKINFO, NULL, 0);
	addNetlinkMsg(&r.n, IFLA_INFO_KIND, dev_type, strlen(dev_type) + 1);
	linkinfo->rta_len = (int)((char*)&r.n + NLMSG_ALIGN(r.n.nlmsg_len) - (char*)linkinfo);

	iovec iov = {&r.n, r.n.nlmsg_len};
	msghdr msg = {sa, sizeof(*sa), &iov, 1, NULL, 0, 0};

	return sendmsg(fd, &msg, 0);
}


static int receive(int fd, sockaddr_nl* sa, void* buf, size_t len) {
	iovec iov;
	msghdr msg {};
	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_name = sa;
	msg.msg_namelen = sizeof(*sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return recvmsg(fd, &msg, 0);
}

static ebpfdiscovery::IpIfce parseIfce(void* data, size_t len) {
	ebpfdiscovery::IpIfce ifce{};
	ifaddrmsg* ifa = (ifaddrmsg*)data;
	if (ifa->ifa_family != AF_INET) {
		return {};
	}

	ifce.index = ifa->ifa_index;
	ifce.mask = htonl(-1 << (32 - ifa->ifa_prefixlen));
	// int family = ifa->ifa_family;
	rtattr* rta = (rtattr*)IFA_RTA(data);

	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		in_addr* addr = (in_addr*)RTA_DATA(rta);

		if (rta->rta_type == IFA_ADDRESS) {
			ifce.ip.push_back(addr->s_addr);
		}
		/*
		if (rta->rta_type == IFA_LOCAL) {
			printf("local address:\t%s\n", inet_ntop(family, addr, ips, INET_ADDRSTRLEN));
		}*/

		if (rta->rta_type == IFA_BROADCAST) {
			ifce.broadcast.push_back(addr->s_addr);
		}
	}

	return ifce;
}

static int parseIfi(void* data, size_t len) {
	ifinfomsg* ifa = (ifinfomsg*)data;
	return ifa->ifi_index;
}

namespace ebpfdiscovery {
bool IpUtils::readNetworks() {
	const bool ret = readAllIpAddrs();
	if (markLocalBridges()) {
		bridgeEnd = moveBridges();
	} else {
		bridgeEnd = localNetsIpv4.end();
	}

	return ret;
}

std::vector<IpIfce>::iterator IpUtils::moveBridges() {
	return std::partition(localNetsIpv4.begin(), localNetsIpv4.end(), [](const auto& it) { return it.isLocalBridge; });
}

template <typename F>
static uint32_t parseNlMsg(void* buf, size_t len, F parse) {
	const nlmsghdr* nl = (nlmsghdr*)buf;

	for (; NLMSG_OK(nl, len) && nl->nlmsg_type != NLMSG_DONE; nl = NLMSG_NEXT(nl, len)) {
		if (nl->nlmsg_type == NLMSG_ERROR) {
			printf("error");
			return -1;
		}

		if (nl->nlmsg_type == RTM_NEWADDR || nl->nlmsg_type == RTM_NEWLINK) {
			parse(NLMSG_DATA(nl), IFA_PAYLOAD(nl));
			continue;
		}
	}
	return nl->nlmsg_type;
}

template <typename S, typename F>
static bool handleNetlink(S send, F f, int domain) {

	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		logError("socket");
		return false;
	}

	auto const _ = gsl::finally([fd]() { ::close(fd); });
	sockaddr_nl sa{};
	sa.nl_family = AF_NETLINK;

	int len = send(fd, &sa, domain);
	if (len <= 0) {
		logError("send");
		return false;
	}

	uint32_t nl_msg_type;
	do {
		std::array<char, BUFLEN> buf{};
		len = receive(fd, &sa, buf.data(), BUFLEN);
		if (len <= 0) {
			logError("receive");
			break;
		}

		nl_msg_type = parseNlMsg(buf.data(), len, f);

	} while (nl_msg_type != NLMSG_DONE && nl_msg_type != NLMSG_ERROR);

	return true;
}

bool IpUtils::readAllIpAddrs() {
	return handleNetlink(
			[](int fd, sockaddr_nl* sa, int domain) { return getIp(fd, sa, AF_INET); },
			[this](void* buf, size_t len) { addIpIfce(parseIfce(buf, len)); }, AF_INET);
}

bool IpUtils::markLocalBridges() {
	return handleNetlink(
			[](int fd, sockaddr_nl* sa, int domain) { return getBridges(fd, sa, AF_INET); },
			[this](void* buf, size_t len) { markBridge(parseIfi(buf, len)); }, AF_INET);
}

void IpUtils::addIpIfce(IpIfce&& ifce) {
	char ifname[IF_NAMESIZE];
	if_indextoname(ifce.index, ifname);
	if (strcmp(ifname, "lo") == 0) {
		return;
	}
	localNetsIpv4.push_back(ifce);
}

void IpUtils::markBridge(int idx) {
	auto ifc = std::find_if(localNetsIpv4.begin(), localNetsIpv4.end(), [idx](const auto& it) { return it.index == idx; });
	if (ifc == localNetsIpv4.end()) {
		return;
	}

	ifc->isLocalBridge = true;
}

void IpUtils::printAll() {
	for (const auto& el : localNetsIpv4) {
		std::cout << el.index << " " << std::hex << "0x" << el.mask << " " << el.isLocalBridge << " ";
		for (const auto addr : el.ip) {
			char ips[INET6_ADDRSTRLEN];
			std::cout << inet_ntop(AF_INET, &addr, ips, INET6_ADDRSTRLEN) << " " << std::hex << addr;
		}
		std::cout << "\n";
	}
}

bool IpUtils::isAddresExternalLocal(IPv4 ip) {

	if ((ip & maskA) != ipA && (ip & maskB) != ipB && (ip & maskC) != ipC) {
		return false;
	}

	const bool bridgeRelated = std::any_of(localNetsIpv4.begin(), bridgeEnd, [ip](const auto& it) {
		return std::any_of(it.ip.begin(), it.ip.end(), [ip, mask = it.mask](const auto& ip2) { return (ip & mask) == (ip2 & mask); });
	});

	if (bridgeRelated) {
		return false;
	}

	return true;
}
}
