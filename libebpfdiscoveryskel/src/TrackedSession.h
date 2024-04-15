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

#include "ebpfdiscoveryshared/Constants.h"
#include "ebpfdiscoveryshared/Types.h"

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

/*
 * Tracked sessions
 */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct DiscoveryTrackedSessionKey);
	__type(value, struct DiscoverySession);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} trackedSessionsMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct DiscoveryTrackedSessionKey);
	__type(value, struct DiscoverySockIPv4);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} trackedSessionSockIPv4Map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct DiscoveryTrackedSessionKey);
	__type(value, struct DiscoverySockIPv6);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} trackedSessionSockIPv6Map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct DiscoverySockIPv4);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} trackedSessionSockIPv4PidTgidMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct DiscoverySockIPv6);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} trackedSessionSockIPv6PidTgidMap SEC(".maps");

__attribute__((always_inline)) inline static struct sockaddr_in* getSockIPv4ForTrackedSession(
		const struct DiscoveryTrackedSessionKey* key, __u64 pidTgid) {
	struct sockaddr_in* sockIpPtr = bpf_map_lookup_elem(&trackedSessionSockIPv4Map, key);
	if (sockIpPtr == NULL) {
		sockIpPtr = bpf_map_lookup_elem(&trackedSessionSockIPv4PidTgidMap, &pidTgid);
	}
	return sockIpPtr;
}

__attribute__((always_inline)) inline static struct sockaddr_in6* getSockIPv6ForTrackedSession(
		const struct DiscoveryTrackedSessionKey* key, __u64 pidTgid) {
	struct sockaddr_in6* sockIpPtr = bpf_map_lookup_elem(&trackedSessionSockIPv6Map, key);
	if (sockIpPtr == NULL) {
		sockIpPtr = bpf_map_lookup_elem(&trackedSessionSockIPv6PidTgidMap, &pidTgid);
	}
	return sockIpPtr;
}

__attribute__((always_inline)) inline static int setSockIPv4ForTrackedSession(
		const struct DiscoveryTrackedSessionKey* key, __u64 pidTgid, struct DiscoverySockIPv4* sockIpPtr) {
	int ret = bpf_map_update_elem(&trackedSessionSockIPv4Map, key, sockIpPtr, BPF_ANY);
	if (ret != 0) {
		return ret;
	}
	return bpf_map_update_elem(&trackedSessionSockIPv4PidTgidMap, &pidTgid, sockIpPtr, BPF_ANY);
}

__attribute__((always_inline)) inline static int setSockIPv6ForTrackedSession(
		const struct DiscoveryTrackedSessionKey* key, __u64 pidTgid, struct DiscoverySockIPv6* sockIpPtr) {
	int ret = bpf_map_update_elem(&trackedSessionSockIPv6Map, key, sockIpPtr, BPF_ANY);
	if (ret != 0) {
		return ret;
	}
	return bpf_map_update_elem(&trackedSessionSockIPv6PidTgidMap, &pidTgid, sockIpPtr, BPF_ANY);
}

__attribute__((always_inline)) inline static int deleteSockIPv4ForTrackedSession(
		const struct DiscoveryTrackedSessionKey* key, __u64 pidTgid) {
	return bpf_map_delete_elem(&trackedSessionSockIPv4Map, key);
}

__attribute__((always_inline)) inline static int deleteSockIPv6ForTrackedSession(
		const struct DiscoveryTrackedSessionKey* key, __u64 pidTgid) {
	return bpf_map_delete_elem(&trackedSessionSockIPv6Map, key);
}

__attribute__((always_inline)) inline static int deleteTrackedSession(struct DiscoveryTrackedSessionKey* key, __u64 pidTgid) {
	int ret = bpf_map_delete_elem(&trackedSessionsMap, key);
	deleteSockIPv4ForTrackedSession(key, pidTgid);
	deleteSockIPv6ForTrackedSession(key, pidTgid);
	return ret;
}

__attribute__((always_inline)) inline static int createTrackedSessionUnencryptedHttp(
		struct DiscoveryAllSessionState* allSessionStatePtr, struct DiscoveryTrackedSessionKey* key) {
	struct DiscoverySession session = {
			.bufferCount = 0, .id = ++allSessionStatePtr->sessionCounter, .flags = DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP};
	return bpf_map_update_elem(&trackedSessionsMap, (struct DiscoveryTrackedSessionKey*)key, &session, BPF_ANY);
}

__attribute__((always_inline)) inline static int createTrackedSessionSslHttp(
		struct DiscoveryAllSessionState* allSessionStatePtr, struct DiscoveryTrackedSessionKey* key) {
	struct DiscoverySession session = {
			.bufferCount = 0, .id = ++allSessionStatePtr->sessionCounter, .flags = DISCOVERY_FLAG_SESSION_SSL_HTTP};
	return bpf_map_update_elem(&trackedSessionsMap, (struct DiscoveryTrackedSessionKey*)key, &session, BPF_ANY);
}

__attribute__((always_inline)) inline static int trackedSessionPutSourceIp(
		struct DiscoverySession* sessionPtr, struct DiscoverySavedBufferKey* key, __u64 pidTgid) {
	void* sockIpPtr = getSockIPv4ForTrackedSession((struct DiscoveryTrackedSessionKey*)key, pidTgid);
	if (sockIpPtr != NULL) {
		discoveryFlagsSessionSetIPv4(&sessionPtr->flags);
		BPF_CORE_READ_INTO(&sessionPtr->sourceIP.data, (struct sockaddr_in*)sockIpPtr, sin_addr);
		bpf_map_delete_elem(&trackedSessionSockIPv4Map, key);
		return 0;
	}

	sockIpPtr = getSockIPv6ForTrackedSession((struct DiscoveryTrackedSessionKey*)key, pidTgid);
	if (sockIpPtr != NULL) {
		discoveryFlagsSessionSetIPv6(&sessionPtr->flags);
		BPF_CORE_READ_INTO(&sessionPtr->sourceIP.data, (struct sockaddr_in6*)sockIpPtr, sin6_addr);
		bpf_map_delete_elem(&trackedSessionSockIPv6Map, key);
		return 0;
	}

	return -1;
}

__attribute__((always_inline)) inline static void trackedSessionSaveBuf(
		struct DiscoverySavedBufferKey* key, const char* buf, size_t bytesCount) {
	DEBUG_PRINTLN("Saving buffer for tracked session. (sessionID:`%d`, bufferSeq:`%d`)", key->sessionID, key->bufferSeq);
	struct DiscoverySavedBuffer* savedBufferPtr = newSavedBuffer();
	if (savedBufferPtr == NULL) {
		return;
	}
	// TODO: replace quirky if statements with bit operations
	if (bytesCount <= sizeof(savedBufferPtr->data)) {
		savedBufferPtr->length = bytesCount;
	} else {
		savedBufferPtr->length = sizeof(savedBufferPtr->data);
	}
	if (savedBufferPtr->length <= 0) {
		return;
	}
	if (savedBufferPtr->length <= sizeof(savedBufferPtr->data)) {
		bpf_probe_read(savedBufferPtr->data, savedBufferPtr->length, buf);
		bpf_map_update_elem(&savedBuffersMap, key, savedBufferPtr, BPF_ANY);
	}
}

__attribute__((always_inline)) inline static void fillTrackedSession(
		struct pt_regs* ctx,
		struct DiscoveryGlobalState* globalStatePtr,
		struct DiscoverySession* sessionPtr,
		struct DiscoverySavedBufferKey* key,
		__u64 pidTgid,
		const char* buf,
		size_t bytesCount) {
	if (!discoveryFlagsSessionIsIPv4(sessionPtr->flags) && !discoveryFlagsSessionIsIPv6(sessionPtr->flags)) {
		if (trackedSessionPutSourceIp(sessionPtr, key, pidTgid) != 0) {
			LOG_TRACE(ctx, "No saved source address of tracked session. (sessionID: `%d`)", sessionPtr->id);
		};
	}

	trackedSessionSaveBuf(key, buf, bytesCount);
}
