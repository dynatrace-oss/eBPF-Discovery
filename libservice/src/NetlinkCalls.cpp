/*
 * Copyright 2023 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "service/NetlinkCalls.h"

#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <linux/rtnetlink.h>
#include <ifaddrs.h>

#include "NetlinkSocket.h"
#include "logging/Logger.h"

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

static int sendIpAddrRequest(const NetlinkSocket& netlinkSocket, sockaddr_nl* dst, int domain) {
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

	return netlinkSocket.send(&msg, 0);
}

static int sendBridgesRequest(const NetlinkSocket& netlinkSocket, sockaddr_nl* dst, int domain) {
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

	return netlinkSocket.send(&msg, 0);
}

static int receive(const NetlinkSocket& netlinkSocket, sockaddr_nl* dst, void* buf, size_t len) {
	iovec iov;
	msghdr msg{};
	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_name = dst;
	msg.msg_namelen = sizeof(*dst);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return netlinkSocket.receive(&msg, 0);
}

static IpInterfaces::value_type parseIfceIPv4(void* data, size_t len) {
	IpIfce ifce{};
	ifaddrmsg* ifa = reinterpret_cast<ifaddrmsg*>(data);
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

	return {ifa->ifa_index, ifce};
}

template <typename T>
T parse(void* data, size_t len);

template <>
IpInterfaces::value_type parse(void* data, size_t len) {
	if (reinterpret_cast<ifaddrmsg*>(data)->ifa_family != AF_INET) {
		return {};
	}

	return parseIfceIPv4(data, len);
}

template <>
BridgeIndices::value_type parse(void* data, size_t len) {
	ifinfomsg* ifa = reinterpret_cast<ifinfomsg*>(data);
	return ifa->ifi_index;
}

template <typename Data>
struct ParseResult {
	uint32_t nlMsgType;
	Data data;
};

void insert(const IpInterfaces::value_type& data, IpInterfaces& ipInterfaces) {
	ipInterfaces.emplace(data);
}

void insert(const BridgeIndices::value_type& data, BridgeIndices& bridgeIndices) {
	bridgeIndices.push_back(data);
}

template <typename Data>
static ParseResult<Data> parseNlMsg(void* buf, size_t len) {
	const nlmsghdr* nl = reinterpret_cast<nlmsghdr*>(buf);
	ParseResult<Data> parseResult{.nlMsgType = nl->nlmsg_type};

	for (; NLMSG_OK(nl, len) && nl->nlmsg_type != NLMSG_DONE; nl = NLMSG_NEXT(nl, len)) {
		if (nl->nlmsg_type == NLMSG_ERROR) {
			const auto err{reinterpret_cast<nlmsgerr*>(NLMSG_DATA(nl))};
			LOG_WARN("Error while receiving netlink message: {}", std::strerror(err->error));
			break;
		}

		if (nl->nlmsg_type == RTM_NEWADDR || nl->nlmsg_type == RTM_NEWLINK) {
			insert(parse<typename Data::value_type>(NLMSG_DATA(nl), IFA_PAYLOAD(nl)), parseResult.data);
		}
	}

	return parseResult;
}

template <typename Data>
Data receive(const NetlinkSocket& netlinkSocket, sockaddr_nl* dst) {
	Data result;
	for (;;) {
		std::array<char, BUFFLEN> buf{};
		const auto len{receive(netlinkSocket, dst, buf.data(), BUFFLEN)};

		if (len <= 0) {
			LOG_WARN("Error while receiving netlink message: {}", strerror(errno));
			break;
		}

		const auto [nlMsgType, data]{parseNlMsg<Data>(buf.data(), len)};

		if (nlMsgType == NLMSG_ERROR) {
			break;
		}

		for (const auto& entry : data) {
			insert(entry, result);
		}

		if (nlMsgType == NLMSG_DONE) {
			break;
		}
	}

	return result;
}

IpInterfaces receiveIpAddr(const NetlinkSocket& netlinkSocket, sockaddr_nl* dst) {
	return receive<IpInterfaces>(netlinkSocket, dst);
}

BridgeIndices receiveBridgeIndex(const NetlinkSocket& netlinkSocket, sockaddr_nl* dst) {
	return receive<BridgeIndices>(netlinkSocket, dst);
}

template <typename Send, typename Receive, typename Data>
Data handleNetlink(const Send& send, const Receive& receive, int domain) {
	NetlinkSocket netlinkSocket;
	if (!netlinkSocket) {
		LOG_WARN("Error while opening netlink socket: {}", strerror(errno));
		return {};
	}

	sockaddr_nl sa{};
	sa.nl_family = AF_NETLINK;

	int len = send(netlinkSocket, &sa, domain);
	if (len <= 0) {
		LOG_WARN("Error while sending netlink request: {}", strerror(errno));
		return {};
	}

	return receive(netlinkSocket, &sa);
}

IpInterfaces NetlinkCalls::collectIpInterfaces() const {
	return handleNetlink<decltype(sendIpAddrRequest), decltype(receiveIpAddr), IpInterfaces>(sendIpAddrRequest, receiveIpAddr, AF_INET);
}

	std::vector<NetlinkCalls::Ipv6Interface> NetlinkCalls::collectIpv6Interfaces() const {
		std::vector<Ipv6Interface> collectedIpv6Interfaces{};

		ifaddrs *ifAddressStruct = nullptr;
		if (getifaddrs(&ifAddressStruct) == 0) {
			for (ifaddrs *ifa = ifAddressStruct; ifa != nullptr; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET6) {
					in6_addr interfaceIpv6Addr = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr)->sin6_addr;
					in6_addr interfaceMask = reinterpret_cast<sockaddr_in6*>(ifa->ifa_netmask)->sin6_addr;

					collectedIpv6Interfaces.emplace_back(Ipv6Interface{interfaceIpv6Addr, interfaceMask});
				}
			}
			freeifaddrs(ifAddressStruct);
		}

		return collectedIpv6Interfaces;
	}

BridgeIndices NetlinkCalls::collectBridgeIndices() const {
	return handleNetlink<decltype(sendBridgesRequest), decltype(receiveBridgeIndex), BridgeIndices>(
			sendBridgesRequest, receiveBridgeIndex, AF_INET);
}

} // namespace service
