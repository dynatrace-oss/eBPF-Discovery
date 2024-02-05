/*
 * Copyright 2023 Dynatrace LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

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
	size_t addrSize;
};

struct ReadArgs {
	__u32 fd;
	char* buf;
};

struct ReadVectorArgs {
	__u32 fd;
	struct iovec* iov;
	size_t iovlen;
};
