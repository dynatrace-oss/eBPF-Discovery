// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "Log.h"
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

__attribute__((always_inline)) inline static void disableDiscoveryCollecting(struct DiscoveryGlobalState* discoveryGlobalStatePtr) {
	DEBUG_PRINT("Discovery disabled.\n");
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
		struct DiscoveryGlobalState* globalStatePtr, struct DiscoveryEvent* eventPtr) {
	int result = bpf_map_push_elem(&eventsToUserspaceQueueMap, eventPtr, BPF_ANY);
	if (result != 0) {
		DEBUG_PRINT("Couldn't push a shared event. pid: `%d`, fd: `%d`\n", eventPtr->dataKey.pid, eventPtr->dataKey.fd);
		disableDiscoveryCollecting(globalStatePtr);
		return result;
	}

	DEBUG_PRINT("Queued a shared event. pid: `%d`, fd: `%d`\n", eventPtr->dataKey.pid, eventPtr->dataKey.fd);
	return result;
}
