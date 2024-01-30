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

__attribute__((always_inline)) inline static void deleteTrackedSession(
		struct DiscoveryTrackedSessionKey* trackedSessionKeyPtr, struct DiscoverySession* sessionPtr) {
	if (sessionPtr->bufferCount == 0 && discoverySessionFlagsIsIPv4(sessionPtr->meta.flags)) {
		bpf_map_delete_elem(&trackedSessionSockIPv4Map, trackedSessionKeyPtr);
	} else if (sessionPtr->bufferCount == 0 && discoverySessionFlagsIsIPv6(sessionPtr->meta.flags)) {
		bpf_map_delete_elem(&trackedSessionSockIPv6Map, trackedSessionKeyPtr);
	}
	bpf_map_delete_elem(&trackedSessionsMap, trackedSessionKeyPtr);
}
