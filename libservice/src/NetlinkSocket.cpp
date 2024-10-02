/*
 * Copyright 2024 Dynatrace LLC
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

#include "NetlinkSocket.h"

#include "logging/Logger.h"
#include <linux/rtnetlink.h>
#include <unistd.h>

namespace service {

NetlinkSocket::NetlinkSocket() : fd{socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)} {
}

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