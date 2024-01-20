// SPDX-License-Identifier: GPL-2.0
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

int handleSSLReadEntry(struct pt_regs* ctx, void* ssl, char* buf) {
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

	__u64 pidTgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&runningLibSSLReadArgsMap, &pidTgid, &sslReadArgs, BPF_ANY);

	return 0;
}

int handleSSLReadExit(struct pt_regs* ctx, int ret) {
	if (ret <= 0) {
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

	// Get arguments of currently handled syscall
	struct LibSSLReadArgs* sslReadArgsPtr = (struct LibSSLReadArgs*)bpf_map_lookup_elem(&runningLibSSLReadArgsMap, &pidTgid);
	if (sslReadArgsPtr == NULL) {
		return 0;
	}

	if (sslReadArgsPtr->ssl == NULL || sslReadArgsPtr->buf == NULL) {
		return 0;
	}

	struct ReadArgs readArgs = {};
	readArgs.fd = getFdFromSslKind(sslReadArgsPtr->ssl, LIBSSL_KIND_OPENSSL_3_0); // TODO
	readArgs.buf = sslReadArgsPtr->buf;
	DEBUG_PRINTLN("%s", sslReadArgsPtr->buf);

	handleRead(ctx, globalStatePtr, allSessionStatePtr, &readArgs, ret, 1);

	return 0;
}

/*
 * Probes
 */

SEC("uprobe/SSL_read:libssl.so.1.1")
int BPF_UPROBE(uprobeOpenSSL1_1SSLRead, void* ssl, void* buf) {
	return handleSSLReadEntry(ctx, ssl, (char*)buf);
}

SEC("uretprobe/SSL_read:libssl.so.1.1")
int BPF_UPROBE(uretprobeOpenSSL1_1SSLRead, int ret) {
	return handleSSLReadExit(ctx, ret);
}

SEC("uprobe/SSL_read:libssl.so.3")
int BPF_UPROBE(uprobeOpenSSL3SSLRead, void* ssl, void* buf) {
	return handleSSLReadEntry(ctx, ssl, (char*)buf);
}

SEC("uretprobe/SSL_read:libssl.so.3")
int BPF_UPROBE(uretprobeOpenSSL3SSLRead, int ret) {
	return handleSSLReadExit(ctx, ret);
}
