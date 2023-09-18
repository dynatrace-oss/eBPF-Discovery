// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "ebpfdiscoveryshared/Constants.h"
#include "ebpfdiscoveryshared/Types.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

/*
 * Tracked sessions
 */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct DiscoveryTrackedSessionKey);
	__type(value, struct DiscoverySession);
	__uint(max_entries, MAX_SESSIONS);
} trackedSessionsMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct DiscoveryTrackedSessionKey);
	__type(value, struct DiscoverySockIPv4);
	__uint(max_entries, MAX_SESSIONS);
} trackedSessionSockIPv4Map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct DiscoveryTrackedSessionKey);
	__type(value, struct DiscoverySockIPv6);
	__uint(max_entries, MAX_SESSIONS);
} trackedSessionSockIPv6Map SEC(".maps");

__attribute__((always_inline)) inline static void deleteTrackedSession(
		struct DiscoveryTrackedSessionKey* trackedSessionKeyPtr, struct DiscoverySession* sessionPtr) {
	if (sessionPtr->bufferCount == 0 && discoverySessionFlagsIsIPv4(sessionPtr->meta.flags)) {
		bpf_map_delete_elem(&trackedSessionSockIPv4Map, trackedSessionKeyPtr);
	} else if (sessionPtr->bufferCount == 0 && discoverySessionFlagsIsIPv6(sessionPtr->meta.flags)) {
		bpf_map_delete_elem(&trackedSessionSockIPv6Map, trackedSessionKeyPtr);
	}
	bpf_map_delete_elem(&trackedSessionsMap, trackedSessionKeyPtr);
}
