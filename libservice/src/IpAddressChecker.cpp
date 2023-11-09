// SPDX-License-Identifier: Apache-2.0
#include "service/IpAddressChecker.h"

#include "logging/Logger.h"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <errno.h>
#include <gsl/util>
#include <iostream>
#include <linux/rtnetlink.h>
#include <string>
#include <string_view>
#include <unistd.h>

static constexpr uint32_t BUFLEN{4096};
static constexpr uint32_t IP_CLASS_C{0x0000a8c0}; // 192.168.*.*
static constexpr uint32_t MASK_CLASS_C{0x0000ffff};
static constexpr uint32_t IP_CLASS_B{0x000010ac}; // 172.16-31.*.*
static constexpr uint32_t MASK_CLASS_B{0x0000f0ff};
static constexpr uint32_t IP_CLASS_A{0x0000000a}; // 10.*.*.*
static constexpr uint32_t MASK_CLASS_A{0x000000ff};
static constexpr uint32_t IP_LINK_LOCAL{0x0000fea9}; // 169.254.*.*
static constexpr uint32_t MASK_LINK_LOCAL{0x0000ffff};
static constexpr uint32_t IP_LOOPBACK{0x0000007f}; // 127.0.*.*
static constexpr uint32_t MASK_LOOPBACK{0x00ffffff};

using IpIfce = service::IpIfce;

static void logErrorFromErrno(std::string_view prefix) {
	std::cout << prefix << ": " << strerror(errno) << "\n";
}

static IpIfce parseIfceIPv4(void* data, size_t len) {
	IpIfce ifce{};
	ifaddrmsg* ifa = reinterpret_cast<ifaddrmsg*>(data);
	ifce.index = ifa->ifa_index;
	ifce.mask = htonl(-1 << (32 - ifa->ifa_prefixlen));
	rtattr* rta = reinterpret_cast<rtattr*>(IFA_RTA(data));

	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		in_addr* addr = reinterpret_cast<in_addr*>(RTA_DATA(rta));

		if (rta->rta_type == IFA_ADDRESS) {
			ifce.ip.push_back(addr->s_addr);
		}

		if (rta->rta_type == IFA_BROADCAST) {
			ifce.broadcast.push_back(addr->s_addr);
		}
	}

	return ifce;
}

static IpIfce parseIfce(void* data, size_t len) {
	if (reinterpret_cast<ifaddrmsg*>(data)->ifa_family != AF_INET) {
		return {};
	}

	return parseIfceIPv4(data, len);
}

static int getIfIndex(void* data) {
	ifinfomsg* ifa = reinterpret_cast<ifinfomsg*>(data);
	return ifa->ifi_index;
}

namespace service {

IpAddressChecker::IpAddressChecker(std::initializer_list<IpIfce> config, const NetlinkCalls& calls) : netlink(calls) {
	interfaces.insert(interfaces.end(), config.begin(), config.end());
}

IpAddressChecker::IpAddressChecker(const NetlinkCalls& calls) : netlink(calls) {
}

bool IpAddressChecker::readNetworks() {
	const bool ret = readAllIpAddrs();
	if (markLocalBridges()) {
		moveBridges();
	} else {
		bridgeEnd = interfaces.end();
	}
	printInfo();
	return ret;
}

void IpAddressChecker::moveBridges() {
	bridgeEnd = std::partition(interfaces.begin(), interfaces.end(), [](const auto& it) { return it.isLocalBridge; });
}

template <typename P>
static uint32_t parseNlMsg(void* buf, size_t len, P parse) {
	const nlmsghdr* nl = reinterpret_cast<nlmsghdr*>(buf);

	for (; NLMSG_OK(nl, len) && nl->nlmsg_type != NLMSG_DONE; nl = NLMSG_NEXT(nl, len)) {
		if (nl->nlmsg_type == NLMSG_ERROR) {
			return -1;
		}

		if (nl->nlmsg_type == RTM_NEWADDR || nl->nlmsg_type == RTM_NEWLINK) {
			parse(NLMSG_DATA(nl), IFA_PAYLOAD(nl));
			continue;
		}
	}

	return nl->nlmsg_type;
}

template <typename S, typename P, typename R>
static bool handleNetlink(S send, R receive, P parse, int domain) {
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		logErrorFromErrno("socket");
		return false;
	}

	auto const _ = gsl::finally([fd]() { ::close(fd); });
	sockaddr_nl sa{};
	sa.nl_family = AF_NETLINK;

	int len = send(fd, &sa, domain);
	if (len <= 0) {
		logErrorFromErrno("send");
		return false;
	}

	uint32_t nlMsgType;
	do {
		std::array<char, BUFLEN> buf{};
		len = receive(fd, &sa, buf.data(), BUFLEN);
		if (len <= 0) {
			logErrorFromErrno("receive");
			break;
		}

		nlMsgType = parseNlMsg(buf.data(), len, parse);
	} while (nlMsgType != NLMSG_DONE && nlMsgType != NLMSG_ERROR);

	return true;
}

void IpAddressChecker::printInfo() {
	char buff[16];
	for (const auto& ifce : interfaces) {
		for (const auto& ip : ifce.ip) {
			LOG_INFO("IfceIdx:{} Ip:{} isLocalBridge:{}", ifce.index, inet_ntop(AF_INET, &ip, buff, sizeof(buff)), ifce.isLocalBridge);
		}
	}
}

bool IpAddressChecker::readAllIpAddrs() {
	return handleNetlink(
			[this](int fd, sockaddr_nl* sa, int domain) { return netlink.sendIpAddrRequest(fd, sa, AF_INET); },
			[this](int fd, sockaddr_nl* dst, void* buf, size_t len) { return netlink.receive(fd, dst, buf, len); },
			[this](void* buf, size_t len) { addIpIfce(parseIfce(buf, len)); },
			AF_INET);
}

bool IpAddressChecker::markLocalBridges() {
	return handleNetlink(
			[this](int fd, sockaddr_nl* sa, int domain) { return netlink.sendBridgesRequest(fd, sa, AF_INET); },
			[this](int fd, sockaddr_nl* dst, void* buf, size_t len) { return netlink.receive(fd, dst, buf, len); },
			[this](void* buf, size_t len) { markBridge(getIfIndex(buf)); },
			AF_INET);
}

void IpAddressChecker::addIpIfce(IpIfce&& ifce) {
	if (!isLoopback(ifce)) {
		interfaces.push_back(ifce);
	}
}

void IpAddressChecker::markBridge(int idx) {
	auto ifc = std::find_if(interfaces.begin(), interfaces.end(), [idx](const auto& it) { return it.index == idx; });
	if (ifc == interfaces.end()) {
		return;
	}

	ifc->isLocalBridge = true;
}

bool IpAddressChecker::isLoopback(const IpIfce& ifce) {

	return std::all_of(ifce.ip.begin(), ifce.ip.end(), [](const auto& ipv4) { return ((ipv4 & MASK_LOOPBACK) == IP_LOOPBACK); });
}

bool IpAddressChecker::isAddressExternalLocal(IPv4int addr) {
	const bool isPublic =
			((addr & MASK_CLASS_A) != IP_CLASS_A) && ((addr & MASK_CLASS_B) != IP_CLASS_B) && ((addr & MASK_CLASS_C) != IP_CLASS_C);

	if (isPublic) {
		return false;
	}

	if ((addr & MASK_LINK_LOCAL) == IP_LINK_LOCAL) {
		return false;
	}

	const bool srcLocal = std::any_of(bridgeEnd, interfaces.end(), [addr](const auto& it) {
		return std::any_of(it.ip.begin(), it.ip.end(), [addr](const auto& ip) { return addr == ip; });
	});

	if (srcLocal) {
		return false;
	}
	const bool bridgeRelated = std::any_of(interfaces.begin(), bridgeEnd, [addr](const auto& it) {
		return std::any_of(it.ip.begin(), it.ip.end(), [addr, mask = it.mask](const auto& ip) { return (addr & mask) == (ip & mask); });
	});

	if (bridgeRelated) {
		return false;
	}

	return true;
}
} // namespace service
