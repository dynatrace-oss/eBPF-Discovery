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
#include "ebpfdiscoveryshared/Constants.h"
#include "ebpfdiscoveryshared/Types.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct DiscoveryGlobalState);
	__uint(max_entries, 1);
} globalStateMap SEC(".maps");

__attribute__((always_inline)) inline static struct DiscoveryGlobalState* getGlobalState() {
	__u32 zero = 0;
	return (struct DiscoveryGlobalState*)bpf_map_lookup_elem(&globalStateMap, &zero);
}

__attribute__((always_inline)) inline static void disableDiscoveryCollecting(
		struct pt_regs* ctx, struct DiscoveryGlobalState* discoveryGlobalStatePtr) {
	LOG_DEBUG(ctx, "Discovery collecting of data has been disabled.")
	discoveryGlobalStatePtr->isCollectingDisabled = true;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct DiscoveryAllSessionState);
	__uint(max_entries, 1);
} allSessionStateMap SEC(".maps");

__attribute__((always_inline)) inline static struct DiscoveryAllSessionState* getAllSessionState() {
	__u32 zero = 0;
	return (struct DiscoveryAllSessionState*)bpf_map_lookup_elem(&allSessionStateMap, &zero);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct DiscoverySavedBuffer);
	__uint(max_entries, 1);
} oneSavedBufferHeapMap SEC(".maps");

__attribute__((always_inline)) inline static struct DiscoverySavedBuffer* newSavedBuffer() {
	__u32 zero = 0;
	return (struct DiscoverySavedBuffer*)bpf_map_lookup_elem(&oneSavedBufferHeapMap, &zero);
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct DiscoverySavedBufferKey);
	__type(value, struct DiscoverySavedBuffer);
	__uint(max_entries, DISCOVERY_MAX_SESSIONS);
} savedBuffersMap SEC(".maps");

__attribute__((always_inline)) inline static void deleteSavedSession(struct DiscoverySavedSessionKey* savedSessionKeyPtr) {
	bpf_map_delete_elem(&savedBuffersMap, savedSessionKeyPtr);
}

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct DiscoveryEvent);
	__uint(max_entries, DISCOVERY_EVENT_QUEUE_SIZE);
} eventsToUserspaceQueueMap SEC(".maps");

__attribute__((always_inline)) inline static int pushEventToUserspace(
		struct pt_regs* ctx, struct DiscoveryGlobalState* globalStatePtr, struct DiscoveryEvent* eventPtr) {
	int result = bpf_map_push_elem(&eventsToUserspaceQueueMap, eventPtr, BPF_ANY);
	if (result != 0) {
		LOG_DEBUG(ctx, "Couldn't push the shared event. (fd: `%d`)", eventPtr->dataKey.fd);
		disableDiscoveryCollecting(ctx, globalStatePtr);
		return result;
	}

	return result;
}
