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

#include "DebugPrint.h"
#include "GlobalData.h"
#include "Handlers.h"
#include "LibSSLTypes.h"

#include "ebpfdiscoveryshared/Constants.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

/*
 * Maps for storing probed function arguments to pass them from uprobes to uretprobes.
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct LibSSLReadArgs);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} runningLibSSLReadArgsMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, struct LibSSLPendingArgs);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} runningLibSSLPendingArgsMap SEC(".maps");

/*
 * Probe handlers
 */

__attribute__((always_inline)) inline static int handleSSLReadExEntry(struct pt_regs* ctx, void* ssl, char* buf, size_t num, size_t* readBytes) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	if (ssl == NULL || buf == NULL) {
		return 0;
	}

	struct LibSSLReadArgs sslReadArgs = {};
	sslReadArgs.ssl = ssl;
	sslReadArgs.buf = buf;
	sslReadArgs.readBytes = readBytes;

	__u64 pidTgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&runningLibSSLReadArgsMap, &pidTgid, &sslReadArgs, BPF_ANY);
	DEBUG_PRINTLN("ssl read entry, pid: `%d`", pidTgidToPid(pidTgid));

	return 0;
}

__attribute__((always_inline)) inline static int handleSSLReadEntry(struct pt_regs* ctx, void* ssl, char* buf, int num) {
	return handleSSLReadExEntry(ctx, ssl, buf, (size_t)num, NULL);
}

__attribute__((always_inline)) inline static int handleSSLReadExit(struct pt_regs* ctx, int bytesCount) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	__u64 pidTgid = bpf_get_current_pid_tgid();

	struct LibSSLReadArgs* sslReadArgsPtr = (struct LibSSLReadArgs*)bpf_map_lookup_elem(&runningLibSSLReadArgsMap, &pidTgid);
	if (sslReadArgsPtr == NULL) {
		return 0;
	}

	if (sslReadArgsPtr->ssl == NULL || sslReadArgsPtr->buf == NULL) {
		return 0;
	}

	int fd = -1;

	if (bytesCount <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd);
		return 0;
	}

	handleReadSslHttp(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd, sslReadArgsPtr->buf, bytesCount);
	DEBUG_PRINTLN("ssl read exit, pid: `%d`, no fd", pidTgidToPid(pidTgid));

	return 0;
}

__attribute__((always_inline)) inline static int handleSSLReadExExit(struct pt_regs* ctx, int ret) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	__u64 pidTgid = bpf_get_current_pid_tgid();

	struct LibSSLReadArgs* sslReadArgsPtr = (struct LibSSLReadArgs*)bpf_map_lookup_elem(&runningLibSSLReadArgsMap, &pidTgid);
	if (sslReadArgsPtr == NULL) {
		return 0;
	}

	if (sslReadArgsPtr->ssl == NULL || sslReadArgsPtr->buf == NULL || sslReadArgsPtr->readBytes == NULL) {
		return 0;
	}

	int fd = -1;

	if (ret <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd);
		return 0;
	}

	size_t bytesCount;
	bpf_probe_read_user(&bytesCount, sizeof(size_t), sslReadArgsPtr->readBytes);
	if (bytesCount <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd);
		return 0;
	}

	handleReadSslHttp(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd, sslReadArgsPtr->buf, bytesCount);
	DEBUG_PRINTLN("ssl read exit, pid: `%d`, no fd", pidTgidToPid(pidTgid));

	return 0;
}

__attribute__((always_inline)) inline static int handleSSLPendingEntry(struct pt_regs* ctx, void* ssl) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	if (ssl == NULL) {
		return 0;
	}

	struct LibSSLPendingArgs sslArgs = {};
	sslArgs.ssl = ssl;

	__u64 pidTgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&runningLibSSLPendingArgsMap, &pidTgid, &sslArgs, BPF_ANY);

	return 0;
}

__attribute__((always_inline)) inline static int handleSSLPendingExit(struct pt_regs* ctx, int ret) {
	struct DiscoveryGlobalState* globalStatePtr = getGlobalState();
	if (globalStatePtr == NULL || globalStatePtr->isCollectingDisabled) {
		return 0;
	}

	struct DiscoveryAllSessionState* allSessionStatePtr = getAllSessionState();
	if (allSessionStatePtr == NULL) {
		return 0;
	};

	__u64 pidTgid = bpf_get_current_pid_tgid();

	struct LibSSLPendingArgs* sslArgsPtr = (struct LibSSLPendingArgs*)bpf_map_lookup_elem(&runningLibSSLPendingArgsMap, &pidTgid);
	if (sslArgsPtr == NULL) {
		return 0;
	}

	if (sslArgsPtr->ssl == NULL) {
		return 0;
	}

	int fd = -1;

	if (ret <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd);
		return 0;
	}

	return 0;
}

/*
 * Probes
 */

// cppcheck-suppress unknownMacro
SEC("uprobe/SSL_read:libssl.so")
int BPF_UPROBE(uprobeSSLReadOpenSSL, void* ssl, void* buf, int num) {
	return handleSSLReadEntry(ctx, ssl, (char*)buf, num);
}

SEC("uretprobe/SSL_read:libssl.so")
int BPF_URETPROBE(uretprobeSSLReadOpenSSL, int ret) {
	return handleSSLReadExit(ctx, ret);
}

SEC("uprobe/SSL_read_ex:libssl.so")
int BPF_UPROBE(uprobeSSLReadExOpenSSL, void* ssl, void* buf, size_t num, size_t* readBytes) {
	return handleSSLReadExEntry(ctx, ssl, (char*)buf, num, readBytes);
}

SEC("uretprobe/SSL_read_ex:libssl.so")
int BPF_URETPROBE(uretprobeSSLReadExOpenSSL, int ret) {
	return handleSSLReadExExit(ctx, ret);
}

SEC("uprobe/SSL_pending:libssl.so")
int BPF_UPROBE(uprobeSSLPendingOpenSSL, void* ssl) {
	return handleSSLPendingEntry(ctx, ssl);
}

SEC("uretprobe/SSL_pending:libssl.so")
int BPF_URETPROBE(uretprobeSSLPendingOpenSSL, int ret) {
	return handleSSLPendingExit(ctx, ret);
}
