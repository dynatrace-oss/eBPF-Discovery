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
#include "Log.h"
#include "SysTypes.h"
#include "TrackedSession.h"

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

/*
 * Probe handlers
 */

int handleSSLReadExEntry(struct pt_regs* ctx, void* ssl, char* buf, size_t* readBytes) {
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

int handleSSLReadEntry(struct pt_regs* ctx, void* ssl, char* buf) {
	return handleSSLReadExEntry(ctx, ssl, buf, NULL);
}

int handleSSLReadExit(struct pt_regs* ctx, int bytesCount) {
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

	if (bytesCount <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, -1);
		return 0;
	}

	handleReadSslHttp(ctx, globalStatePtr, allSessionStatePtr, pidTgid, -1, sslReadArgsPtr->buf, bytesCount);
	DEBUG_PRINTLN("ssl read exit, pid: `%d`, no fd", pidTgidToPid(pidTgid));

	return 0;
}

int handleSSLReadExExit(struct pt_regs* ctx, int ret) {
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

	if (ret <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, -1);
		return 0;
	}

	size_t bytesCount;
	bpf_probe_read_user(&bytesCount, sizeof(size_t), sslReadArgsPtr->readBytes);
	if (bytesCount <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, -1);
		return 0;
	}

	handleReadSslHttp(ctx, globalStatePtr, allSessionStatePtr, pidTgid, -1, sslReadArgsPtr->buf, bytesCount);
	DEBUG_PRINTLN("ssl read exit, pid: `%d`, no fd", pidTgidToPid(pidTgid));

	return 0;
}

int handleSSLReadExitWithVersion(struct pt_regs* ctx, int bytesCount, enum LibSSLKind kind) {
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

	int fd = getFdFromSslKind(sslReadArgsPtr->ssl, kind);
	if (fd < 0) {
		LOG_DEBUG(ctx, "Invalid file descriptor from SSL struct for pid %d.", pidTgidToPid(pidTgid));
		fd = -1;
	}

	if (bytesCount <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd);
		return 0;
	}

	handleReadSslHttp(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd, sslReadArgsPtr->buf, bytesCount);
	DEBUG_PRINTLN("ssl read exit, pid: `%d`, fd: `%d`", pidTgidToPid(pidTgid), fd);

	return 0;
}

int handleSSLReadExExitWithVersion(struct pt_regs* ctx, int ret, enum LibSSLKind kind) {
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

	int fd = getFdFromSslKind(sslReadArgsPtr->ssl, kind);
	if (fd < 0) {
		LOG_DEBUG(ctx, "Invalid file descriptor from SSL struct for pid %d.", pidTgidToPid(pidTgid));
		fd = -1;
	}

	if (ret <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, -1);
		return 0;
	}

	size_t bytesCount;
	bpf_probe_read_user(&bytesCount, sizeof(size_t), sslReadArgsPtr->readBytes);
	if (bytesCount <= 0) {
		handleNoMoreData(ctx, globalStatePtr, allSessionStatePtr, pidTgid, -1);
		return 0;
	}

	handleReadSslHttp(ctx, globalStatePtr, allSessionStatePtr, pidTgid, fd, sslReadArgsPtr->buf, bytesCount);
	DEBUG_PRINTLN("ssl read exit, pid: `%d`, fd: `%d`", pidTgidToPid(pidTgid), fd);

	return 0;
}

/*
 * Probes
 */

SEC("uprobe/SSL_read:libssl.so")
int BPF_UPROBE(uprobeSSLReadOpenSSL, void* ssl, void* buf) {
	return handleSSLReadEntry(ctx, ssl, (char*)buf);
}

SEC("uprobe/SSL_read_ex:libssl.so")
int BPF_UPROBE(uprobeSSLReadExOpenSSL, void* ssl, void* buf, size_t* readBytes) {
	return handleSSLReadExEntry(ctx, ssl, (char*)buf, readBytes);
}

SEC("uretprobe/SSL_read:libssl.so")
int BPF_URETPROBE(uretprobeSSLReadOpenSSL, int ret) {
	return handleSSLReadExit(ctx, ret);
}

SEC("uretprobe/SSL_read_ex:libssl.so")
int BPF_URETPROBE(uretprobeSSLReadExOpenSSL, int ret) {
	return handleSSLReadExExit(ctx, ret);
}

SEC("uretprobe/SSL_read:libssl.so.1.0.2")
int BPF_URETPROBE(uretprobeSSLReadOpenSSL1_0_2, int ret) {
	return handleSSLReadExitWithVersion(ctx, ret, LIBSSL_KIND_OPENSSL_1_0_2);
}

SEC("uretprobe/SSL_read_ex:libssl.so.1.0.2")
int BPF_URETPROBE(uretprobeSSLReadExOpenSSL1_0_2, int ret) {
	return handleSSLReadExExitWithVersion(ctx, ret, LIBSSL_KIND_OPENSSL_1_0_2);
}

SEC("uretprobe/SSL_read:libssl.so.1.1.0")
int BPF_URETPROBE(uretprobeSSLReadOpenSSL1_1_0, int ret) {
	return handleSSLReadExitWithVersion(ctx, ret, LIBSSL_KIND_OPENSSL_1_1_0);
}

SEC("uretprobe/SSL_read_ex:libssl.so.1.1.0")
int BPF_URETPROBE(uretprobeSSLReadExOpenSSL1_1_0, int ret) {
	return handleSSLReadExExitWithVersion(ctx, ret, LIBSSL_KIND_OPENSSL_1_1_0);
}

SEC("uretprobe/SSL_read:libssl.so.1.1.1")
int BPF_URETPROBE(uretprobeSSLReadOpenSSL1_1_1, int ret) {
	return handleSSLReadExitWithVersion(ctx, ret, LIBSSL_KIND_OPENSSL_1_1_1);
}

SEC("uretprobe/SSL_read_ex:libssl.so.1.1.1")
int BPF_URETPROBE(uretprobeSSLReadExOpenSSL1_1_1, int ret) {
	return handleSSLReadExExitWithVersion(ctx, ret, LIBSSL_KIND_OPENSSL_1_1_1);
}

SEC("uretprobe/SSL_read:libssl.so.3.0")
int BPF_URETPROBE(uretprobeSSLReadOpenSSL3_0, int ret) {
	return handleSSLReadExitWithVersion(ctx, ret, LIBSSL_KIND_OPENSSL_3_0);
}

SEC("uretprobe/SSL_read:libssl.so.3.0")
int BPF_URETPROBE(uretprobeSSLReadExOpenSSL3_0, int ret) {
	return handleSSLReadExExitWithVersion(ctx, ret, LIBSSL_KIND_OPENSSL_3_0);
}
