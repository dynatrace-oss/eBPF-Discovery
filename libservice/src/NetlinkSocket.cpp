// SPDX-License-Identifier: Apache-2.0

#include "NetlinkSocket.h"

#include <linux/rtnetlink.h>
#include <unistd.h>
#include "logging/Logger.h"

namespace service {

NetlinkSocket::NetlinkSocket() : fd{socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)} {}

NetlinkSocket::~NetlinkSocket() {
	close(fd);
}

ssize_t NetlinkSocket::send(const msghdr* message, int flags) const {
	return sendmsg(fd, message, flags);
}

ssize_t NetlinkSocket::receive(msghdr* message, int flags) const {
	return recvmsg(fd, message, flags);
}

} // namespace service