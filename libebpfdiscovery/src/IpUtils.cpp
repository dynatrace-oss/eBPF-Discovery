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

static int get_ip(int fd, struct sockaddr_nl* sa, int domain) {
	std::array<char, BUFLEN> buf{};

	struct nlmsghdr* nl;
	nl = (struct nlmsghdr*)buf.data();
	nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nl->nlmsg_type = RTM_GETADDR;
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

	struct ifaddrmsg* ifa;
	ifa = (struct ifaddrmsg*)NLMSG_DATA(nl);
	ifa->ifa_family = domain; // ipv4 or ipv6

	struct iovec iov = {nl, nl->nlmsg_len};
	struct msghdr msg = {sa, sizeof(*sa), &iov, 1, NULL, 0, 0};

	return sendmsg(fd, &msg, 0);
}

static void add_netlink_msg(struct nlmsghdr* nh, int type, const void* data, int raw_data_length) {
	struct rtattr* rta;
	int rta_length = RTA_LENGTH(raw_data_length);

	rta = (struct rtattr*)((char*)nh + NLMSG_ALIGN(nh->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = rta_length;
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta_length);

	memcpy(RTA_DATA(rta), data, raw_data_length);
}

static int get_bridges(int fd, struct sockaddr_nl* sa, int domain) {
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char _[1024]; // required
	} r;

	memset(&r, 0, sizeof(r));
	const char* dev_type = "bridge";

	r.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	r.n.nlmsg_type = RTM_GETLINK;
	r.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	r.i.ifi_family = AF_PACKET;
	r.n.nlmsg_pid = 0;
	r.n.nlmsg_seq = 0;

	struct rtattr* linkinfo = (struct rtattr*)((char*)&r.n + NLMSG_ALIGN(r.n.nlmsg_len));
	add_netlink_msg(&r.n, IFLA_LINKINFO, NULL, 0);
	add_netlink_msg(&r.n, IFLA_INFO_KIND, dev_type, strlen(dev_type) + 1);
	linkinfo->rta_len = (int)((char*)&r.n + NLMSG_ALIGN(r.n.nlmsg_len) - (char*)linkinfo);

	struct iovec iov = {&r.n, r.n.nlmsg_len};
	struct msghdr msg = {sa, sizeof(*sa), &iov, 1, NULL, 0, 0};

	return sendmsg(fd, &msg, 0);
}

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

static int receive(int fd, struct sockaddr_nl* sa, void* buf, size_t len) {
	struct iovec iov;
	struct msghdr msg {};
	iov.iov_base = buf;
	iov.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = sa;
	msg.msg_namelen = sizeof(*sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return recvmsg(fd, &msg, 0);
}

static IpIfce parse_ifce(void* data, size_t len) {
	IpIfce ifce{};
	struct ifaddrmsg* ifa = (struct ifaddrmsg*)data;
	if (ifa->ifa_family != AF_INET) {
		return {};
	}

	ifce.index = ifa->ifa_index;
	ifce.mask = htonl(-1 << (32 - ifa->ifa_prefixlen));
	// int family = ifa->ifa_family;
	struct rtattr* rta = (struct rtattr*)IFA_RTA(data);

	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		struct in_addr* addr = (in_addr*)RTA_DATA(rta);

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

static int parse_ifi(void* data, size_t len) {
	struct ifinfomsg* ifa = (struct ifinfomsg*)data;
	return ifa->ifi_index;
}

template <typename F>
static uint32_t parse_nl_msg(void* buf, size_t len, F parse) {
	const struct nlmsghdr* nl = (struct nlmsghdr*)buf;

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
static bool handleNetlink(S send, F f) {

	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		logError("socket");
		return false;
	}

	auto const _ = gsl::finally([fd]() { ::close(fd); });
	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	int len = send(fd, &sa, AF_INET); // To get ipv6, use AF_INET6 instead
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

		nl_msg_type = parse_nl_msg(buf.data(), len, f);

	} while (nl_msg_type != NLMSG_DONE && nl_msg_type != NLMSG_ERROR);

	return true;
}

bool IpUtils::readAllIpAddrs() {
	return handleNetlink(
			[](int fd, struct sockaddr_nl* sa, int domain) { return get_ip(fd, sa, AF_INET); },
			[this](void* buf, size_t len) { addIpIfce(parse_ifce(buf, len)); });
}

bool IpUtils::markLocalBridges() {
	return handleNetlink(
			[](int fd, struct sockaddr_nl* sa, int domain) { return get_bridges(fd, sa, AF_INET); },
			[this](void* buf, size_t len) { markBridge(parse_ifi(buf, len)); });
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
