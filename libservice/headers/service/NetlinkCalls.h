// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <stddef.h>

struct sockaddr_nl;

namespace service {

class NetlinkCalls {
public:
	virtual int sendIpAddrRequest(int fd, sockaddr_nl* dst, int domain) const;
	virtual int sendBridgesRequest(int fd, sockaddr_nl* dst, int domain) const;
	virtual int receive(int fd, sockaddr_nl* dst, void* buf, size_t len) const;
};
} // namespace service
