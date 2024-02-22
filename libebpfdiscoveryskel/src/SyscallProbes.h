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

#include "GlobalData.h"
#include "Handlers.h"
#include "SysPrefixMacro.h"
#include "SysTypes.h"
#include "TrackedSession.h"
#include "ebpfdiscoveryshared/Constants.h"

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Maps for storing syscall arguments to pass them from kprobes to kretprobes.
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct AcceptSyscallArgs);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} runningAcceptSyscallArgsMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct ReadSyscallScalarArgs);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} runningReadSyscallScalarArgsMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct ReadSyscallVectorArgs);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} runningReadSyscallVectorArgsMap SEC(".maps");

/*
 * Syscall handlers
 */

__attribute__((always_inline)) inline static int handleSysAcceptEntry(struct pt_regs* ctx, struct sockaddr* addr, socklen_t* addrlen) {
	if (addr == NULL || addrlen == NULL) {
		// We expect that for TCP/IP connections the addr argument is not null.
		return 0;
	}

	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	struct AcceptSyscallArgs acceptSyscallArgs = {};
	acceptSyscallArgs.addr = addr;
	acceptSyscallArgs.addrlen = addrlen;

	bpf_probe_read(&acceptSyscallArgs.addrSize, sizeof(acceptSyscallArgs.addrSize), addrlen);
	if (acceptSyscallArgs.addrSize < sizeof(short unsigned int)) {
		// addrSize is the size of sockaddr struct allocated by calling program. If sockaddr isn't big enough to store
		// the sa_family field, we exit early.
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&runningAcceptSyscallArgsMap, &pid_tgid, &acceptSyscallArgs, BPF_ANY);
	return 0;
}

__attribute__((always_inline)) inline static int handleSysAcceptExit(struct pt_regs* ctx, int fd) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	__u64 pidTgid = bpf_get_current_pid_tgid();

	// Get arguments of currently being handled accept
	struct AcceptSyscallArgs* acceptSyscallArgsPtr = bpf_map_lookup_elem(&runningAcceptSyscallArgsMap, &pidTgid);
	if (acceptSyscallArgsPtr == NULL) {
		return 0;
	}

	if (fd < 0) {
		bpf_map_delete_elem(&runningAcceptSyscallArgsMap, &pidTgid);
		return 0;
	}

	handleAccept(ctx, acceptSyscallArgsPtr, fd);

	bpf_map_delete_elem(&runningAcceptSyscallArgsMap, &pidTgid);
	return 0;
}

__attribute__((always_inline)) inline static int handleSysReadEntry(struct pt_regs* ctx, int fd, char* buf) {
	if (buf == NULL) {
		return 0;
	}

	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	__u64 pidTgid = bpf_get_current_pid_tgid();

	struct DiscoveryTrackedSessionKey trackedSessionKey = {};
	trackedSessionKey.pid = pidTgidToPid(pidTgid);
	trackedSessionKey.fd = fd;

	if (bpf_map_lookup_elem(&trackedSessionsMap, &trackedSessionKey) == NULL) {
		// If the read call is not part of a being handled session, stop handling the syscall
		return 0;
	}

	struct ReadSyscallScalarArgs readSyscallScalarArgs = {
			.fd = trackedSessionKey.fd,
			.buf = buf,
	};

	bpf_map_update_elem(&runningReadSyscallScalarArgsMap, &pidTgid, &readSyscallScalarArgs, BPF_ANY);
	return 0;
}

__attribute__((always_inline)) inline static int handleSysReadExit(struct pt_regs* ctx, ssize_t bytesCount) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	__u64 pidTgid = bpf_get_current_pid_tgid();

	// Get arguments of currently handled syscall
	struct ReadSyscallScalarArgs* readSyscallScalarArgsPtr = (struct ReadSyscallScalarArgs*)bpf_map_lookup_elem(&runningReadSyscallScalarArgsMap, &pidTgid);
	if (readSyscallScalarArgsPtr == NULL) {
		return 0;
	}

	struct ReadSyscallHandlerArgs readSyscallHandlerArgs = {
			.fd = readSyscallScalarArgsPtr->fd,
			.buf = readSyscallScalarArgsPtr->buf,
			.bytesCount = bytesCount,
	};

	handleRead(ctx, globalStatePtr, allSessionStatePtr, &readSyscallHandlerArgs, pidTgid);
	bpf_map_delete_elem(&runningReadSyscallScalarArgsMap, &pidTgid);

	return 0;
}

__attribute__((always_inline)) inline static int handleSysCloseEntry(struct pt_regs* ctx, int fd) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	handleClose(ctx, globalStatePtr, allSessionStatePtr, fd);
	return 0;
}

__attribute__((always_inline)) inline static bool dropMessageHandling(struct pt_regs* ctx, int fd, int flags) {
	if (flags & MSG_PEEK) {
		return true;
	}

	if (flags & MSG_TRUNC || flags & MSG_OOB) {
		// We drop session handling as well when these flags are used
		handleSysCloseEntry(ctx, fd);
		return true;
	}

	return false;
}

__attribute__((always_inline)) inline static int handleSysRecvEntry(struct pt_regs* ctx, int fd, char* buf, int flags) {
	if (dropMessageHandling(ctx, fd, flags)) {
		return 0;
	}

	handleSysReadEntry(ctx, fd, buf);
	return 0;
}

__attribute__((always_inline)) inline static int handleSysRecvExit(struct pt_regs* ctx, ssize_t bytesCount) {
	return handleSysReadExit(ctx, bytesCount);
}

__attribute__((always_inline)) inline static int handleSysRecvmsgEntry(struct pt_regs* ctx, int sockfd, struct user_msghdr* msg, int flags) {
	if (dropMessageHandling(ctx, sockfd, flags)) {
		return 0;
	}

	if (msg == NULL) {
		return 0;
	}

	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	__u64 pidTgid = bpf_get_current_pid_tgid();

	struct DiscoveryTrackedSessionKey trackedSessionKey = {};
	trackedSessionKey.pid = pidTgidToPid(pidTgid);
	trackedSessionKey.fd = sockfd;

	if (bpf_map_lookup_elem(&trackedSessionsMap, &trackedSessionKey) == NULL) {
		// If the read call is not part of a being handled session, stop handling the syscall
		return 0;
	}

	struct ReadSyscallVectorArgs readSyscallVectorArgs = {};
	readSyscallVectorArgs.fd = trackedSessionKey.fd;
	bpf_probe_read(&readSyscallVectorArgs.iov, sizeof(struct iovec*), &msg->msg_iov);
	bpf_probe_read(&readSyscallVectorArgs.iovlen, sizeof(size_t), &msg->msg_iovlen);

	bpf_map_update_elem(&runningReadSyscallVectorArgsMap, &pidTgid, &readSyscallVectorArgs, BPF_ANY);
	
	return 0;
}

__attribute__((always_inline)) inline static int handleSysRecvmsgExit(struct pt_regs* ctx, ssize_t bytesCount) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	__u64 pidTgid = bpf_get_current_pid_tgid();

	struct ReadSyscallVectorArgs* readSyscallVectorArgsPtr = (struct ReadSyscallVectorArgs*)bpf_map_lookup_elem(&runningReadSyscallVectorArgsMap, &pidTgid);
	if (readSyscallVectorArgsPtr == NULL) {
		return 0;
	}

	if (readSyscallVectorArgsPtr->iov == NULL) {
		return 0;
	}

	if (bytesCount <= 0) {
		bpf_map_delete_elem(&runningReadSyscallVectorArgsMap, &pidTgid);

		return 0;
	}

	for (size_t i = 0; i < DISCOVERY_HANDLER_MAX_IOVLEN && i < readSyscallVectorArgsPtr->iovlen; i++) {
		struct ReadSyscallScalarArgs readSyscallScalarArgs = {
				.fd = readSyscallVectorArgsPtr->fd,
		};

		bpf_probe_read(&readSyscallScalarArgs.buf, sizeof(void*), &readSyscallVectorArgsPtr->iov[i].iov_base);
		if (readSyscallScalarArgs.buf == NULL) {
			handleNoMoreDataForReading(ctx, globalStatePtr, allSessionStatePtr, readSyscallScalarArgs.fd, pidTgid);
			return 0;
		}

		size_t iovLen;
		bpf_probe_read(&iovLen, sizeof(size_t), &readSyscallVectorArgsPtr->iov[i].iov_len);

		struct ReadSyscallHandlerArgs readSyscallHandlerArgs = {
				.fd = readSyscallScalarArgs.fd,
				.buf = readSyscallScalarArgs.buf,
				.bytesCount = (ssize_t) iovLen,
		};

		handleRead(ctx, globalStatePtr, allSessionStatePtr, &readSyscallHandlerArgs, pidTgid);
	}

	bpf_map_delete_elem(&runningReadSyscallVectorArgsMap, &pidTgid);

	return 0;
}

/*
 * Syscall probes
 */

SEC("kprobe/" SYS_PREFIX "sys_accept")
int BPF_KPROBE_SYSCALL(kprobeSysAccept, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
	return handleSysAcceptEntry(ctx, addr, addrlen);
}

SEC("kretprobe/" SYS_PREFIX "sys_accept")
int BPF_KRETPROBE(kretprobeSysAccept, int fd) {
	return handleSysAcceptExit(ctx, fd);
}

SEC("kprobe/" SYS_PREFIX "sys_accept4")
int BPF_KPROBE_SYSCALL(kprobeSysAccept4, int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) {
	return handleSysAcceptEntry(ctx, addr, addrlen);
}

SEC("kretprobe/" SYS_PREFIX "sys_accept4")
int BPF_KRETPROBE(kretprobeSysAccept4, int fd) {
	return handleSysAcceptExit(ctx, fd);
}

SEC("kprobe/" SYS_PREFIX "sys_read")
int BPF_KPROBE_SYSCALL(kprobeSysRead, int fd, void* buf, size_t count) {
	return handleSysReadEntry(ctx, fd, (char*)buf);
}

SEC("kretprobe/" SYS_PREFIX "sys_read")
int BPF_KRETPROBE(kretprobeSysRead, ssize_t bytesCount) {
	return handleSysReadExit(ctx, bytesCount);
}

SEC("kprobe/" SYS_PREFIX "sys_recv")
int BPF_KPROBE_SYSCALL(kprobeSysRecv, int fd, void* buf, size_t len, int flags) {
	return handleSysRecvEntry(ctx, fd, (char*)buf, flags);
}

SEC("kretprobe/" SYS_PREFIX "sys_recv")
int BPF_KRETPROBE(kretprobeSysRecv, ssize_t bytesCount) {
	return handleSysRecvExit(ctx, bytesCount);
}

SEC("kprobe/" SYS_PREFIX "sys_recvmsg")
int BPF_KPROBE_SYSCALL(kprobeSysRecvmsg, int sockfd, struct user_msghdr *msg, int flags) {
	return handleSysRecvmsgEntry(ctx, sockfd, msg, flags);
}

SEC("kretprobe/" SYS_PREFIX "sys_recvmsg")
int BPF_KRETPROBE(kretprobeSysRecvmsg, ssize_t bytesCount) {
	return handleSysRecvmsgExit(ctx, bytesCount);
}

SEC("kprobe/" SYS_PREFIX "sys_recvfrom")
int BPF_KPROBE_SYSCALL(kprobeSysRecvfrom, int fd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen) {
	return handleSysRecvEntry(ctx, fd, (char*)buf, flags);
}

SEC("kretprobe/" SYS_PREFIX "sys_recvfrom")
int BPF_KRETPROBE(kretprobeSysRecvfrom, ssize_t bytesCount) {
	return handleSysRecvExit(ctx, bytesCount);
}

SEC("kprobe/" SYS_PREFIX "sys_close")
int BPF_KPROBE_SYSCALL(kprobeSysClose, int fd) {
	return handleSysCloseEntry(ctx, fd);
}
