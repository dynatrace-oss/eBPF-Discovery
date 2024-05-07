/*
 * Copyright 2023 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "Constants.h"

#ifdef __TARGET_BPF
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
	char data[DISCOVERY_BUFFER_MAX_DATA_SIZE];
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
 * Session state and event flags bitmask
 */

typedef __u8 DiscoveryFlags;

#define DISCOVERY_FLAG_SESSION_IPV4 2
#define DISCOVERY_FLAG_SESSION_IPV6 4
#define DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP 8
#define DISCOVERY_FLAG_SESSION_SSL_HTTP 16
#define DISCOVERY_FLAG_EVENT_NEW_DATA 32
#define DISCOVERY_FLAG_EVENT_DATA_END 64

__attribute__((always_inline)) inline static bool discoveryFlagsEventIsNewData(DiscoveryFlags flags) {
	return flags & DISCOVERY_FLAG_EVENT_NEW_DATA;
}

__attribute__((always_inline)) inline static void discoveryFlagsEventSetNewData(DiscoveryFlags* flags) {
	*flags |= DISCOVERY_FLAG_EVENT_NEW_DATA;
}

__attribute__((always_inline)) inline static bool discoveryFlagsEventIsDataEnd(DiscoveryFlags flags) {
	return flags & DISCOVERY_FLAG_EVENT_DATA_END;
}

__attribute__((always_inline)) inline static void discoveryFlagsEventSetDataEnd(DiscoveryFlags* flags) {
	*flags |= DISCOVERY_FLAG_EVENT_DATA_END;
}

__attribute__((always_inline)) inline static bool discoveryFlagsSessionIsUnencryptedHttp(DiscoveryFlags flags) {
	return flags & DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP;
}

__attribute__((always_inline)) inline static void discoveryFlagsSessionSetUnencryptedHttp(DiscoveryFlags* flags) {
	*flags |= DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP;
}

__attribute__((always_inline)) inline static bool discoveryFlagsSessionIsSslHttp(DiscoveryFlags flags) {
	return flags & DISCOVERY_FLAG_SESSION_SSL_HTTP;
}

__attribute__((always_inline)) inline static void discoveryFlagsSessionSetSslHttp(DiscoveryFlags* flags) {
	*flags |= DISCOVERY_FLAG_SESSION_SSL_HTTP;
}

__attribute__((always_inline)) inline static bool discoveryFlagsSessionIsIPv4(DiscoveryFlags discoveryFlags) {
	return discoveryFlags & DISCOVERY_FLAG_SESSION_IPV4;
}

__attribute__((always_inline)) inline static void discoveryFlagsSessionSetIPv4(DiscoveryFlags* discoveryFlags) {
	*discoveryFlags |= DISCOVERY_FLAG_SESSION_IPV4;
	*discoveryFlags &= ~DISCOVERY_FLAG_SESSION_IPV6;
}

__attribute__((always_inline)) inline static bool discoveryFlagsSessionIsIPv6(DiscoveryFlags discoveryFlags) {
	return discoveryFlags & DISCOVERY_FLAG_SESSION_IPV6;
}

__attribute__((always_inline)) inline static void discoveryFlagsSessionSetIPv6(DiscoveryFlags* discoveryFlags) {
	*discoveryFlags |= DISCOVERY_FLAG_SESSION_IPV6;
	*discoveryFlags &= ~DISCOVERY_FLAG_SESSION_IPV4;
}

/*
 * Session
 */

struct DiscoverySockSourceIP {
	__u8 data[16];
};

struct DiscoverySession {
	__u32 id;
	__u32 bufferCount;
	struct DiscoverySockSourceIP sourceIP;
	DiscoveryFlags flags;
};

/*
 * Shared event
 */

// Event sent from eBPF to userspace program
struct DiscoveryEvent {
	struct DiscoverySavedBufferKey key;
	struct DiscoverySockSourceIP sourceIP;
	DiscoveryFlags flags;
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

/*
 * eBPF logs and program config
 */

enum DiscoveryLogLevel {
	DISCOVERY_LOG_LEVEL_TRACE,
	DISCOVERY_LOG_LEVEL_DEBUG,
	DISCOVERY_LOG_LEVEL_OFF,
};

struct DiscoveryConfig {
	enum DiscoveryLogLevel logLevel;
};

typedef __u64 DiscoveryLogEventArg;

struct DiscoveryLogEvent {
	__u64 timestamp;
	__u64 cpuId;
	__u64 pidTgid;
	enum DiscoveryLogLevel severity;
	char format[DISCOVERY_LOG_MAX_FORMAT_LENGTH];
	DiscoveryLogEventArg args[DISCOVERY_LOG_MAX_ARGS_COUNT];
};
