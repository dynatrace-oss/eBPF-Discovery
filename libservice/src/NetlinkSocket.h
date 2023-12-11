// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <net/if.h>

namespace service {

class NetlinkSocket {
public:
	NetlinkSocket();
	~NetlinkSocket();

	ssize_t send(const msghdr* message, int flags) const;
	ssize_t receive(msghdr* message, int flags) const;

	explicit operator bool() const {
		return fd != -1;
	}

private:
	int fd;
};

} // namespace service
