// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "vmlinux.h"

// Refer to sys/socket.h and bits/socket.h Linux headers

#ifndef AF_INET
#	define AF_INET 2
#endif

#ifndef AF_INET6
#	define AF_INET6 10
#endif

#ifndef MSG_OOB
#	define MSG_OOB 0x01
#endif

#ifndef MSG_PEEK
#	define MSG_PEEK 0x02
#endif

#ifndef MSG_TRUNC
#	define MSG_TRUNC 0x20
#endif

typedef int socklen_t;

struct AcceptArgs {
	struct sockaddr* addr;
	socklen_t* addrlen;

	// Size of sockaddr struct allocated by calling program
	int addrSize;
};

struct ReadArgs {
	__u32 fd;
	char* buf;
};
