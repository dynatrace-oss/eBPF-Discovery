// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "DataReading.h"
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
		const struct DiscoveryTrackedSessionKey tracked_session_key, const struct AcceptArgs* acceptArgsPtr, int addrlen) {
	if (acceptArgsPtr->addrSize < sizeof(struct sockaddr_in) || addrlen != sizeof(struct sockaddr_in)) {
		return;
	}

	struct DiscoverySession session = {};
	discoverySessionFlagsSetIPv4(&session.meta.flags);
	// session.timestamp will be initialized on the first read() call

	struct DiscoverySockIPv4 sockIPv4 = {};
	bpf_probe_read(&sockIPv4.addr, sizeof(struct sockaddr_in), acceptArgsPtr->addr);

	bpf_map_update_elem(&trackedSessionSockIPv4Map, &tracked_session_key, &sockIPv4, BPF_ANY);
	bpf_map_update_elem(&trackedSessionsMap, &tracked_session_key, &session, BPF_ANY);
}

__attribute__((always_inline)) inline static void handleAcceptIPv6Session(
		const struct DiscoveryTrackedSessionKey tracked_session_key, const struct AcceptArgs* acceptArgsPtr, int addrlen) {
	if (acceptArgsPtr->addrSize < sizeof(struct sockaddr_in6) || addrlen != sizeof(struct sockaddr_in6)) {
		return;
	}

	struct DiscoverySession session = {};
	discoverySessionFlagsSetIPv6(&session.meta.flags);
	// session.timestamp will be initialized on the first read() call

	struct DiscoverySockIPv6 sockIPv6 = {};
	bpf_probe_read(&sockIPv6.addr, sizeof(struct sockaddr_in6), acceptArgsPtr->addr);

	bpf_map_update_elem(&trackedSessionSockIPv6Map, &tracked_session_key, &sockIPv6, BPF_ANY);
	bpf_map_update_elem(&trackedSessionsMap, &tracked_session_key, &session, BPF_ANY);
}

__attribute__((always_inline)) inline static void discoveryHandleAccept(struct AcceptArgs* acceptArgsPtr, int fd) {
	// Size of returned sockaddr struct
	int addrlen = 0;
	bpf_probe_read(&addrlen, sizeof(addrlen), (acceptArgsPtr->addrlen));

	if (addrlen == 0) {
		// We expect a source address in TCP/IP sessions
		return;
	}

	short unsigned int saFamily = 0;
	bpf_probe_read(&saFamily, sizeof(saFamily), acceptArgsPtr->addr);

	if (saFamily != AF_INET && saFamily != AF_INET6) {
		return;
	}

	struct DiscoveryTrackedSessionKey trackedSessionKey = {.pid = pidTgidToPid(bpf_get_current_pid_tgid()), .fd = fd};

	switch (saFamily) {
	case AF_INET:
		handleAcceptIPv4Session(trackedSessionKey, acceptArgsPtr, addrlen);
		break;
	case AF_INET6:
		handleAcceptIPv6Session(trackedSessionKey, acceptArgsPtr, addrlen);
		break;
	}
}

__attribute__((always_inline)) inline static int session_init_fill_saddr_ipv4(
		struct DiscoveryTrackedSessionKey* sessionKeyPtr, struct DiscoverySession* sessionPtr) {
	struct sockaddr_in* addrPtr = (struct sockaddr_in*)bpf_map_lookup_elem(&trackedSessionSockIPv4Map, sessionKeyPtr);
	if (addrPtr == NULL) {
		DEBUG_PRINT("No IPv4 of tracked session. (id: %d)\n", sessionPtr->id);
		return 1;
	}

	BPF_CORE_READ_INTO(&sessionPtr->meta.sourceIPData, addrPtr, sin_addr);
	bpf_map_delete_elem(&trackedSessionSockIPv4Map, sessionKeyPtr);
	return 0;
}

__attribute__((always_inline)) inline static int session_init_fill_saddr_ipv6(
		struct DiscoveryTrackedSessionKey* sessionKeyPtr, struct DiscoverySession* sessionPtr) {
	struct sockaddr_in6* addr_ptr = (struct sockaddr_in6*)bpf_map_lookup_elem(&trackedSessionSockIPv6Map, sessionKeyPtr);
	if (addr_ptr == NULL) {
		DEBUG_PRINT("No IPv6 of tracked session. (id: %d)\n", sessionPtr->id);
		return 1;
	}

	BPF_CORE_READ_INTO(&sessionPtr->meta.sourceIPData, addr_ptr, sin6_addr);
	bpf_map_delete_elem(&trackedSessionSockIPv6Map, sessionKeyPtr);
	return 0;
}

__attribute__((always_inline)) inline static int session_init_fill_saddr(
		struct DiscoveryTrackedSessionKey* session_key_ptr, struct DiscoverySession* sessionPtr) {
	if (discoverySessionFlagsIsIPv4(sessionPtr->meta.flags)) {
		return session_init_fill_saddr_ipv4(session_key_ptr, sessionPtr);
	} else if (discoverySessionFlagsIsIPv6(sessionPtr->meta.flags)) {
		return session_init_fill_saddr_ipv6(session_key_ptr, sessionPtr);
	}

	return -1;
}

__attribute__((always_inline)) inline static bool probe_buf_and_check_is_http_beginning(const char* buf, size_t length) {
	// We collect only GET and POST requests. We expect request URI's to start with a slash as absolute urls are mainly used in
	// requests to proxy servers.
	return length >= MIN_HTTP_REQUEST_LENGTH && (dataReadingStreq(buf, "GET /", 5) || dataReadingStreq(buf, "POST /", 6));
}

__attribute__((always_inline)) inline static void discoveryHandleRead(
		struct DiscoveryGlobalState* globalStatePtr,
		struct DiscoveryAllSessionState* allSessionStatePtr,
		struct ReadArgs* readArgsPtr,
		ssize_t bytesCount) {
	if (bytesCount <= 0) {
		// No data to handle
		return;
	}

	struct DiscoveryEvent event = {.flags = DISCOVERY_EVENT_FLAGS_NEW_DATA};
	event.dataKey.pid = pidTgidToPid(bpf_get_current_pid_tgid());
	event.dataKey.fd = readArgsPtr->fd;

	struct DiscoverySession* sessionPtr =
			(struct DiscoverySession*)bpf_map_lookup_elem(&trackedSessionsMap, (struct DiscoveryTrackedSessionKey*)&event.dataKey);
	if (sessionPtr == NULL) {
		// The read call is not part of a tracked session
		return;
	}

	if (sessionPtr->bufferCount == 0) {
		if (!probe_buf_and_check_is_http_beginning(readArgsPtr->buf, bytesCount)) {
			deleteTrackedSession((struct DiscoveryTrackedSessionKey*)&event.dataKey, sessionPtr);
			DEBUG_PRINT(
					"Received data from session. Ignoring the session, as it doesn't look like an HTTP request. pid: `%d`, fd: `%d`, "
					"bytes_count: `%d`\n",
					event.dataKey.pid,
					event.dataKey.fd,
					bytesCount);
			return;
		}

		sessionPtr->id = allSessionStatePtr->sessionCounter;
		allSessionStatePtr->sessionCounter++;
		session_init_fill_saddr((struct DiscoveryTrackedSessionKey*)&event.dataKey, sessionPtr);
	} else {
		event.dataKey.bufferSeq = sessionPtr->bufferCount;
	}

	event.dataKey.sessionID = sessionPtr->id;
	event.sessionMeta = sessionPtr->meta;

	struct DiscoverySavedBuffer* savedBufferPtr = newSavedBuffer();
	if (savedBufferPtr == NULL) {
		return;
	}

	if (bytesCount <= sizeof(savedBufferPtr->data)) {
		savedBufferPtr->length = bytesCount;
	} else {
		savedBufferPtr->length = sizeof(savedBufferPtr->data);
	}

	if (savedBufferPtr->length <= sizeof(savedBufferPtr->data)) {
		bpf_probe_read(savedBufferPtr->data, savedBufferPtr->length, readArgsPtr->buf);
		bpf_map_update_elem(&savedBuffersMap, &event.dataKey, savedBufferPtr, BPF_ANY);
	}

	pushEventToUserspace(globalStatePtr, &event);

	if (discoveryEventFlagsIsNoMoreData(event.flags)) {
		deleteTrackedSession((struct DiscoveryTrackedSessionKey*)&event.dataKey, sessionPtr);
		return;
	}

	sessionPtr->bufferCount++;
}

__attribute__((always_inline)) inline static void discoveryHandleClose(
		struct DiscoveryGlobalState* globalStatePtr, struct DiscoveryAllSessionState* allSessionStatePtr, int fd) {
	struct DiscoveryTrackedSessionKey trackedSessionKey = {};
	trackedSessionKey.pid = pidTgidToPid(bpf_get_current_pid_tgid());

	struct DiscoverySession* sessionPtr = (struct DiscoverySession*)bpf_map_lookup_elem(&trackedSessionsMap, &trackedSessionKey);
	if (sessionPtr == NULL) {
		return;
	}

	// The session should've been removed by userspace by now, when parsed successfully or discarded in other way.
	// Otherwise, send the close event.

	deleteTrackedSession(&trackedSessionKey, sessionPtr);

	struct DiscoveryEvent event = {.flags = DISCOVERY_EVENT_FLAGS_CLOSE};
	pushEventToUserspace(globalStatePtr, &event);
}
