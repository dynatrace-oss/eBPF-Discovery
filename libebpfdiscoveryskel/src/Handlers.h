// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "DataFunctions.h"
#include "DebugPrint.h"
#include "GlobalData.h"
#include "Log.h"
#include "Pid.h"
#include "SysTypes.h"
#include "TrackedSession.h"
#include "ebpfdiscoveryshared/Constants.h"
#include "ebpfdiscoveryshared/Types.h"

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__attribute__((always_inline)) inline static void handleAcceptIPv4Session(
		struct pt_regs* ctx,
		const struct DiscoveryTrackedSessionKey trackedSessionKey,
		const struct AcceptArgs* acceptArgsPtr,
		int addrlen) {
	if (acceptArgsPtr->addrSize < sizeof(struct sockaddr_in) || addrlen != sizeof(struct sockaddr_in)) {
		return;
	}

	struct DiscoverySession session = {};
	discoverySessionFlagsSetIPv4(&session.meta.flags);
	// Session fields are initialized on session's first read() call

	struct DiscoverySockIPv4 sockIPv4 = {};
	bpf_probe_read(&sockIPv4.addr, sizeof(struct sockaddr_in), acceptArgsPtr->addr);

	bpf_map_update_elem(&trackedSessionSockIPv4Map, &trackedSessionKey, &sockIPv4, BPF_ANY);
	bpf_map_update_elem(&trackedSessionsMap, &trackedSessionKey, &session, BPF_ANY);
}

__attribute__((always_inline)) inline static void handleAcceptIPv6Session(
		struct pt_regs* ctx,
		const struct DiscoveryTrackedSessionKey trackedSessionKey,
		const struct AcceptArgs* acceptArgsPtr,
		int addrlen) {
	if (acceptArgsPtr->addrSize < sizeof(struct sockaddr_in6) || addrlen != sizeof(struct sockaddr_in6)) {
		return;
	}

	struct DiscoverySession session = {};
	discoverySessionFlagsSetIPv6(&session.meta.flags);
	// session.timestamp will be initialized on the first read() call

	struct DiscoverySockIPv6 sockIPv6 = {};
	bpf_probe_read(&sockIPv6.addr, sizeof(struct sockaddr_in6), acceptArgsPtr->addr);

	bpf_map_update_elem(&trackedSessionSockIPv6Map, &trackedSessionKey, &sockIPv6, BPF_ANY);
	bpf_map_update_elem(&trackedSessionsMap, &trackedSessionKey, &session, BPF_ANY);
}

__attribute__((always_inline)) inline static void handleAccept(struct pt_regs* ctx, struct AcceptArgs* acceptArgsPtr, int fd) {
	// Size of returned sockaddr struct
	int addrlen = 0;
	bpf_probe_read(&addrlen, sizeof(addrlen), (acceptArgsPtr->addrlen));
	fd = 1337;

	if (addrlen == 0) {
		// We expect a source address in TCP/IP sessions
		return;
	}

	DEBUG_PRINTLN("handleAccept pid=%d fd=%d", bpf_get_current_pid_tgid(), fd);

	short unsigned int saFamily = 0;
	bpf_probe_read(&saFamily, sizeof(saFamily), acceptArgsPtr->addr);

	if (saFamily != AF_INET && saFamily != AF_INET6) {
		return;
	}

	struct DiscoveryTrackedSessionKey trackedSessionKey = {.pid = pidTgidToPid(bpf_get_current_pid_tgid()), .fd = fd};

	switch (saFamily) {
	case AF_INET:
		handleAcceptIPv4Session(ctx, trackedSessionKey, acceptArgsPtr, addrlen);
		break;
	case AF_INET6:
		handleAcceptIPv6Session(ctx, trackedSessionKey, acceptArgsPtr, addrlen);
		break;
	}
}

__attribute__((always_inline)) inline static int sessionFillIPv4(
		struct pt_regs* ctx, struct DiscoveryTrackedSessionKey* sessionKeyPtr, struct DiscoverySession* sessionPtr) {
	struct sockaddr_in* sockipPtr = (struct sockaddr_in*)bpf_map_lookup_elem(&trackedSessionSockIPv4Map, sessionKeyPtr);
	if (sockipPtr == NULL) {
		LOG_DEBUG(ctx, "No IPv4 of tracked session. (id: `%d`)", sessionPtr->id);
		return 1;
	}

	BPF_CORE_READ_INTO(&sessionPtr->meta.sourceIPData, sockipPtr, sin_addr);
	bpf_map_delete_elem(&trackedSessionSockIPv4Map, sessionKeyPtr);
	return 0;
}

__attribute__((always_inline)) inline static int sessionFillIPv6(
		struct pt_regs* ctx, struct DiscoveryTrackedSessionKey* sessionKeyPtr, struct DiscoverySession* sessionPtr) {
	struct sockaddr_in6* sockipPtr = (struct sockaddr_in6*)bpf_map_lookup_elem(&trackedSessionSockIPv6Map, sessionKeyPtr);
	if (sockipPtr == NULL) {
		LOG_DEBUG(ctx, "No IPv6 of tracked session. (id: `%d`)", sessionPtr->id);
		return 1;
	}

	BPF_CORE_READ_INTO(&sessionPtr->meta.sourceIPData, sockipPtr, sin6_addr);
	bpf_map_delete_elem(&trackedSessionSockIPv6Map, sessionKeyPtr);
	return 0;
}

__attribute__((always_inline)) inline static int sessionFillIP(
		struct pt_regs* ctx, struct DiscoveryTrackedSessionKey* sessionKeyPtr, struct DiscoverySession* sessionPtr) {
	if (discoverySessionFlagsIsIPv4(sessionPtr->meta.flags)) {
		return sessionFillIPv4(ctx, sessionKeyPtr, sessionPtr);
	} else if (discoverySessionFlagsIsIPv6(sessionPtr->meta.flags)) {
		return sessionFillIPv6(ctx, sessionKeyPtr, sessionPtr);
	}

	return -1;
}

__attribute__((always_inline)) inline static void handleRead(
		struct pt_regs* ctx,
		struct DiscoveryGlobalState* globalStatePtr,
		struct DiscoveryAllSessionState* allSessionStatePtr,
		struct ReadArgs* readArgsPtr,
		ssize_t bytesCount,
		int isUprobe) {
	if (bytesCount <= 0) {
		// No data to handle
		return;
	}
	readArgsPtr->fd = 1337;

	struct DiscoveryEvent event = {.flags = DISCOVERY_EVENT_FLAGS_NEW_DATA};
	event.dataKey.pid = pidTgidToPid(bpf_get_current_pid_tgid());
	event.dataKey.fd = readArgsPtr->fd;

	struct DiscoverySession* sessionPtr =
			(struct DiscoverySession*)bpf_map_lookup_elem(&trackedSessionsMap, (struct DiscoveryTrackedSessionKey*)&event.dataKey);
	if (sessionPtr == NULL) {
		// The read call is not part of a tracked session
		DEBUG_PRINTLN("handleRead pid=%d fd=%d isUprobe=%d no session", event.dataKey.pid, event.dataKey.fd, isUprobe);
		return;
	}

	if (sessionPtr->bufferCount == 0) {
		if (isUprobe != 0 && !dataProbeIsBeginningOfHttpRequest(readArgsPtr->buf, bytesCount)) {
			DEBUG_PRINTLN("handleRead pid=%d fd=%d isUprobe=%d not http", event.dataKey.pid, event.dataKey.fd, isUprobe);
			deleteTrackedSession((struct DiscoveryTrackedSessionKey*)&event.dataKey, sessionPtr);
			return;
		}

		sessionPtr->id = allSessionStatePtr->sessionCounter;
		sessionPtr->meta.pid = event.dataKey.pid;
		allSessionStatePtr->sessionCounter++;
		sessionFillIP(ctx, (struct DiscoveryTrackedSessionKey*)&event.dataKey, sessionPtr);

		DEBUG_PRINTLN("handleRead pid=%d fd=%d track session sessionID=%d", event.dataKey.pid, event.dataKey.fd, sessionPtr->id);
		DEBUG_PRINTLN("handleRead sessionID=%d isUprobe=%d", sessionPtr->id, isUprobe);
	} else {
		event.dataKey.bufferSeq = sessionPtr->bufferCount;
	}

	event.dataKey.sessionID = sessionPtr->id;
	event.sessionMeta = sessionPtr->meta;

	struct DiscoverySavedBuffer* savedBufferPtr = newSavedBuffer();
	if (savedBufferPtr == NULL) {
		return;
	}

	savedBufferPtr->length = LIMIT_INTEGER_MAX(bytesCount, (int)sizeof(savedBufferPtr->data));

	bpf_probe_read_user(savedBufferPtr->data, savedBufferPtr->length, readArgsPtr->buf);
	bpf_map_update_elem(&savedBuffersMap, &event.dataKey, savedBufferPtr, BPF_ANY);

	if (savedBufferPtr->length != bytesCount) {
		discoveryEventFlagsSetNoMoreData(&event.flags);
	}

	DEBUG_PRINTLN("handleRead sessionID=%d push event to userspace", event.dataKey.sessionID);
	pushEventToUserspace(ctx, globalStatePtr, &event);

	if (discoveryEventFlagsIsNoMoreData(event.flags)) {
		deleteTrackedSession((struct DiscoveryTrackedSessionKey*)&event.dataKey, sessionPtr);
		return;
	}

	sessionPtr->bufferCount++;
}

__attribute__((always_inline)) inline static void handleClose(
		struct pt_regs* ctx, struct DiscoveryGlobalState* globalStatePtr, struct DiscoveryAllSessionState* allSessionStatePtr, int fd) {
	struct DiscoveryTrackedSessionKey trackedSessionKey = {};
	trackedSessionKey.pid = pidTgidToPid(bpf_get_current_pid_tgid());

	struct DiscoverySession* sessionPtr = (struct DiscoverySession*)bpf_map_lookup_elem(&trackedSessionsMap, &trackedSessionKey);
	if (sessionPtr == NULL) {
		return;
	}

	// DEBUG_PRINTLN("handleClose sessionID=%d", sessionPtr->id);

	// The session should've been removed by userspace by now, when parsed successfully or discarded in other way.
	// Otherwise, send the close event.

	// deleteTrackedSession(&trackedSessionKey, sessionPtr);

	struct DiscoveryEvent event = {.flags = DISCOVERY_EVENT_FLAGS_CLOSE};
	// pushEventToUserspace(ctx, globalStatePtr, &event);
}
