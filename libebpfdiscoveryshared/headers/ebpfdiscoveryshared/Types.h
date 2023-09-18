// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "Constants.h"

#ifdef TARGET_BPF
#	include "vmlinux.h"
#else
#	include <linux/types.h>
#	include <netinet/in.h>
#endif

#include <stdbool.h>

#ifdef __cplusplus
#	include <boost/functional/hash.hpp>
#	include <cstddef>
#	include <functional>
#endif

/*
 * Basic types
 */

struct DiscoveryIPv4 {
	__u8 data[4];
};

struct DiscoveryIPv6 {
	__u8 data[16];
};

// Saved source ipv4 address from arguments of an accept() call
struct DiscoverySockIPv4 {
	struct sockaddr_in addr;
};

// Saved source ipv6 address from arguments of an accept() call
struct DiscoverySockIPv6 {
	struct sockaddr_in6 addr;
};

struct DiscoverySavedBuffer {
	__u32 length;
	char data[BUFFER_MAX_DATA_SIZE];
};

/*
 * BPF map key types
 */

struct DiscoveryTrackedSessionKey {
	__u32 pid;
	__u32 fd;
};

struct DiscoverySavedSessionKey {
	__u32 pid;
	__u32 fd;
	__u32 sessionID;

#ifdef __cplusplus
	bool operator==(const DiscoverySavedSessionKey& other) const {
		return pid == other.pid && fd == other.fd && sessionID == other.sessionID;
	}
	operator DiscoveryTrackedSessionKey() const {
		DiscoveryTrackedSessionKey res = {.pid = pid, .fd = fd};
		return res;
	}
#endif
};

#ifdef __cplusplus
struct DiscoverySavedSessionKeyHash {
	std::size_t operator()(const DiscoverySavedSessionKey& key) const {
		std::size_t seed = 0;
		boost::hash_combine(seed, key.pid);
		boost::hash_combine(seed, key.fd);
		boost::hash_combine(seed, key.sessionID);
		return seed;
	}
};
#endif

struct DiscoverySavedBufferKey {
	__u32 pid;
	__u32 fd;
	__u32 sessionID;
	__u32 bufferSeq;

#ifdef __cplusplus
	operator DiscoverySavedSessionKey() const {
		DiscoverySavedSessionKey res = {.pid = pid, .fd = fd, .sessionID = sessionID};
		return res;
	}
	operator DiscoveryTrackedSessionKey() const {
		DiscoveryTrackedSessionKey res = {.pid = pid, .fd = fd};
		return res;
	}
#endif
};

/*
 * Session state bitmask
 */

typedef __u8 DiscoverySessionFlags;

#define DISCOVERY_SESSION_FLAGS_IPV4 0x02
#define DISCOVERY_SESSION_FLAGS_IPV6 0x04

__attribute__((always_inline)) inline static bool discoverySessionFlagsIsIPv4(DiscoverySessionFlags session_flags) {
	return session_flags & DISCOVERY_SESSION_FLAGS_IPV4;
}

__attribute__((always_inline)) inline static void discoverySessionFlagsSetIPv4(DiscoverySessionFlags* session_flags) {
	*session_flags |= DISCOVERY_SESSION_FLAGS_IPV4;
	*session_flags &= ~DISCOVERY_SESSION_FLAGS_IPV6;
}

__attribute__((always_inline)) inline static bool discoverySessionFlagsIsIPv6(DiscoverySessionFlags session_flags) {
	return session_flags & DISCOVERY_SESSION_FLAGS_IPV6;
}

__attribute__((always_inline)) inline static void discoverySessionFlagsSetIPv6(DiscoverySessionFlags* session_flags) {
	*session_flags |= DISCOVERY_SESSION_FLAGS_IPV6;
	*session_flags &= ~DISCOVERY_SESSION_FLAGS_IPV4;
}

/*
 * Session
 */

struct DiscoverySessionMeta {
	__u8 sourceIPData[16];
	DiscoverySessionFlags flags;
};

struct DiscoverySession {
	__u32 id;
	__u32 bufferCount;
	struct DiscoverySessionMeta meta;
};

/*
 * Shared event flags bitmask
 */

typedef __u8 DiscoveryEventFlags;

#define DISCOVERY_EVENT_FLAGS_NEW_DATA 0x01
#define DISCOVERY_EVENT_FLAGS_NO_MORE_DATA 0x02
#define DISCOVERY_EVENT_FLAGS_CLOSE 0x04

__attribute__((always_inline)) inline static bool discoveryEventFlagsIsNewData(DiscoveryEventFlags flags) {
	return flags & DISCOVERY_EVENT_FLAGS_NEW_DATA;
}

__attribute__((always_inline)) inline static void discoveryEventFlagsSetNewData(DiscoveryEventFlags* flags) {
	*flags |= DISCOVERY_EVENT_FLAGS_NEW_DATA;
}

__attribute__((always_inline)) inline static bool discoveryEventFlagsIsNoMoreData(DiscoveryEventFlags flags) {
	return flags & DISCOVERY_EVENT_FLAGS_NO_MORE_DATA;
}

__attribute__((always_inline)) inline static void discoveryEventFlagsSetNoMoreData(DiscoveryEventFlags* flags) {
	*flags |= DISCOVERY_EVENT_FLAGS_NO_MORE_DATA;
}

__attribute__((always_inline)) inline static bool discoveryEventFlagsIsClose(DiscoveryEventFlags flags) {
	return flags & DISCOVERY_EVENT_FLAGS_CLOSE;
}

__attribute__((always_inline)) inline static void discoveryEventFlagsSetClose(DiscoveryEventFlags* flags) {
	*flags |= DISCOVERY_EVENT_FLAGS_CLOSE;
}

/*
 * Shared event
 */

// Event sent from eBPF to userspace program
struct DiscoveryEvent {
	struct DiscoverySavedBufferKey dataKey;
	struct DiscoverySessionMeta sessionMeta;
	DiscoveryEventFlags flags;
};

/*
 * Global eBPF program state
 */

struct DiscoveryAllSessionState {
	__u32 sessionCounter;
};

struct DiscoveryGlobalState {
	bool isCollectingDisabled;
};
