// SPDX-License-Identifier: GPL-2.0
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
	__type(value, struct AcceptArgs);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} runningAcceptArgsMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct ReadArgs);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} runningReadArgsMap SEC(".maps");

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

	struct AcceptArgs acceptArgs = {};
	acceptArgs.addr = addr;
	acceptArgs.addrlen = addrlen;

	bpf_probe_read(&acceptArgs.addrSize, sizeof(acceptArgs.addrSize), addrlen);
	if (acceptArgs.addrSize < sizeof(short unsigned int)) {
		// addrSize is the size of sockaddr struct allocated by calling program. If sockaddr isn't big enough to store
		// the sa_family field, we exit early.
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&runningAcceptArgsMap, &pid_tgid, &acceptArgs, BPF_ANY);
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
	struct AcceptArgs* acceptArgsPtr = bpf_map_lookup_elem(&runningAcceptArgsMap, &pidTgid);
	if (acceptArgsPtr == NULL) {
		return 0;
	}

	if (fd < 0) {
		bpf_map_delete_elem(&runningAcceptArgsMap, &pidTgid);
		return 0;
	}

	handleAccept(ctx, acceptArgsPtr, fd);

	bpf_map_delete_elem(&runningAcceptArgsMap, &pidTgid);
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

	struct ReadArgs readArgs = {
			.fd = trackedSessionKey.fd,
			.buf = buf,
	};

	bpf_map_update_elem(&runningReadArgsMap, &pidTgid, &readArgs, BPF_ANY);
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
	struct ReadArgs* readArgsPtr = (struct ReadArgs*)bpf_map_lookup_elem(&runningReadArgsMap, &pidTgid);
	if (readArgsPtr == NULL) {
		return 0;
	}

	handleRead(ctx, globalStatePtr, allSessionStatePtr, readArgsPtr, bytesCount);
	bpf_map_delete_elem(&runningReadArgsMap, &pidTgid);

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

__attribute__((always_inline)) inline static int handleSysRecvEntry(struct pt_regs* ctx, int fd, char* buf, int flags) {
	if (flags & MSG_PEEK) {
		return 0;
	}

	if (flags & MSG_TRUNC || flags & MSG_OOB) {
		// We drop handling the session when these flags are used
		handleSysCloseEntry(ctx, fd);
		return 0;
	}

	handleSysReadEntry(ctx, fd, buf);
	return 0;
}

__attribute__((always_inline)) inline static int handleSysRecvExit(struct pt_regs* ctx, ssize_t bytesCount) {
	return handleSysReadExit(ctx, bytesCount);
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
