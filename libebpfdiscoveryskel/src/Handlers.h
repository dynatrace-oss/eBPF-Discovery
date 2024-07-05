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

#include "DataFunctions.h"
#include "DebugPrint.h"
#include "GlobalData.h"
#include "Pid.h"
#include "SysTypes.h"
#include "TrackedSession.h"
#include "ebpfdiscoveryshared/Constants.h"
#include "ebpfdiscoveryshared/Types.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__attribute__((always_inline)) inline static void handleAcceptIPv4Session(
		struct pt_regs* ctx,
		const struct DiscoveryTrackedSessionKey* trackedSessionKey,
		__u64 pidTgid,
		const struct AcceptSyscallArgs* acceptSyscallArgsPtr,
		int addrlen) {
	if (acceptSyscallArgsPtr->addrSize < sizeof(struct sockaddr_in) || addrlen != sizeof(struct sockaddr_in)) {
		return;
	}

	struct DiscoverySockIPv4 sockIPv4 = {};
	bpf_probe_read(&sockIPv4.addr, sizeof(struct sockaddr_in), acceptSyscallArgsPtr->addr);
	setSockIPv4ForTrackedSession(trackedSessionKey, pidTgid, &sockIPv4);
	DEBUG_PRINTLN("saved ipv4 pid: `%d`, fd: `%d`, addr: `%d`", trackedSessionKey->pid, trackedSessionKey->fd, acceptSyscallArgsPtr->addr);
}

__attribute__((always_inline)) inline static void handleAcceptIPv6Session(
		struct pt_regs* ctx,
		const struct DiscoveryTrackedSessionKey* trackedSessionKey,
		__u64 pidTgid,
		const struct AcceptSyscallArgs* acceptSyscallArgsPtr,
		int addrlen) {
	if (acceptSyscallArgsPtr->addrSize < sizeof(struct sockaddr_in6) || addrlen != sizeof(struct sockaddr_in6)) {
		return;
	}

	struct DiscoverySockIPv6 sockIPv6 = {};
	bpf_probe_read(&sockIPv6.addr, sizeof(struct sockaddr_in6), acceptSyscallArgsPtr->addr);
	setSockIPv6ForTrackedSession(trackedSessionKey, pidTgid, &sockIPv6);
	DEBUG_PRINTLN("saved ipv6 pid: `%d`, fd: `%d`, addr: `%d`", trackedSessionKey->pid, trackedSessionKey->fd, acceptSyscallArgsPtr->addr);
}

__attribute__((always_inline)) inline static void handleAccept(
		struct pt_regs* ctx,
		struct DiscoveryAllSessionState* allSessionStatePtr,
		__u64 pidTgid,
		struct AcceptSyscallArgs* acceptSyscallArgsPtr,
		int fd) {
	// Size of returned sockaddr struct
	int addrlen = 0;
	bpf_probe_read(&addrlen, sizeof(addrlen), (acceptSyscallArgsPtr->addrlen));

	if (addrlen == 0) {
		// We expect a source address in TCP/IP sessions
		return;
	}

	short unsigned int saFamily = 0;
	bpf_probe_read(&saFamily, sizeof(saFamily), acceptSyscallArgsPtr->addr);

	if (saFamily != AF_INET && saFamily != AF_INET6) {
		return;
	}

	struct DiscoveryTrackedSessionKey key = {.pid = pidTgidToPid(pidTgid), .fd = fd};
	const struct DiscoverySession* sessionPtr =
			(struct DiscoverySession*)bpf_map_lookup_elem(&trackedSessionsMap, (struct DiscoveryTrackedSessionKey*)&key);
	if (sessionPtr == NULL) {
		createTrackedSessionUnencryptedHttp(allSessionStatePtr, &key);
	}
	switch (saFamily) {
	case AF_INET:
		handleAcceptIPv4Session(ctx, &key, pidTgid, acceptSyscallArgsPtr, addrlen);
		break;
	case AF_INET6:
		handleAcceptIPv6Session(ctx, &key, pidTgid, acceptSyscallArgsPtr, addrlen);
		break;
	}
}

__attribute__((always_inline)) inline static void fillTrackedSessionAndPushEvent(
		struct pt_regs* ctx,
		struct DiscoveryGlobalState* globalStatePtr,
		struct DiscoverySession* sessionPtr,
		struct DiscoverySavedBufferKey* key,
		__u64 pidTgid,
		const char* buf,
		size_t bytesCount) {
	// XXX: line below causes invalid bpf_context access off=335 size=1
	//fillTrackedSession(ctx, globalStatePtr, sessionPtr, key, pidTgid, buf, bytesCount);
	struct DiscoveryEvent event = {};
	event.key = *key;
	event.sourceIP = sessionPtr->sourceIP;
	event.flags = sessionPtr->flags | DISCOVERY_FLAG_EVENT_NEW_DATA;
	// XXX: line below causes invalid bpf_context access off=335 size=1
	//pushEventToUserspace(ctx, globalStatePtr, &event);
}

__attribute__((always_inline)) inline static void advanceTrackedSession(
		struct DiscoverySavedBufferKey* key, struct DiscoverySession* sessionPtr) {
	key->bufferSeq = ++sessionPtr->bufferCount;
	DEBUG_PRINTLN("New buffer for tracked session. (sessionID: `%d`, bufferCount: `%d`)", sessionPtr->id, key->bufferSeq);
}

__attribute__((always_inline)) inline static void handleReadUnencryptedHttp(
		struct pt_regs* ctx,
		struct DiscoveryGlobalState* globalStatePtr,
		struct DiscoveryAllSessionState* allSessionStatePtr,
		struct DiscoverySession* sessionPtr,
		__u64 pidTgid,
		__u32 fd,
		const char* buf,
		size_t bytesCount) {
	struct DiscoverySavedBufferKey key = {.pid = pidTgidToPid(pidTgid), .fd = fd};

	if (sessionPtr->bufferCount == 0 && !dataProbeIsBeginningOfHttpRequest(buf, bytesCount)) {
		return;
	} else {
		if (sessionPtr->bufferCount == 0) {
			DEBUG_PRINTLN("New tracked session. (unencrypted http, pid: `%d`, fd: `%d`, sessionID: `%d`)", key.pid, key.fd, sessionPtr->id);
		}
		advanceTrackedSession(&key, sessionPtr);
	}

	key.sessionID = sessionPtr->id;
	key.bufferSeq = sessionPtr->bufferCount;
	fillTrackedSessionAndPushEvent(ctx, globalStatePtr, sessionPtr, &key, pidTgid, buf, bytesCount);
}

__attribute__((always_inline)) inline static void handleReadSslHttp(
		struct pt_regs* ctx,
		struct DiscoveryGlobalState* globalStatePtr,
		struct DiscoveryAllSessionState* allSessionStatePtr,
		__u64 pidTgid,
		__u32 fd,
		const char* buf,
		size_t bytesCount) {
	struct DiscoverySavedBufferKey key = {.pid = pidTgidToPid(pidTgid), .fd = fd, .sessionID = 0, .bufferSeq = 0};
	struct DiscoverySession* sessionPtr =
			(struct DiscoverySession*)bpf_map_lookup_elem(&trackedSessionsMap, (struct DiscoveryTrackedSessionKey*)&key);

	if (sessionPtr != NULL && sessionPtr->bufferCount == 0) {
		advanceTrackedSession(&key, sessionPtr);
	// XXX: line below causes invalid bpf_context access off=335 size=1
	//} else if (dataProbeIsBeginningOfHttpRequest(buf, bytesCount)) {
	} else if (true) {
		// XXX: line below causes invalid bpf_context access off=335 size=1
		//createTrackedSessionSslHttp(allSessionStatePtr, (struct DiscoveryTrackedSessionKey*)&key);
		sessionPtr = (struct DiscoverySession*)bpf_map_lookup_elem(&trackedSessionsMap, (struct DiscoveryTrackedSessionKey*)&key);
		if (sessionPtr == NULL) {
			return;
		}
		DEBUG_PRINTLN("Created new tracked session. (libssl https, pid: `%d`, fd: `%d`, sessionID: `%d`)", key.pid, key.fd, sessionPtr->id);
	} else {
		bpf_map_delete_elem(&trackedSessionsMap, &key);
		return;
	}

	key.sessionID = sessionPtr->id;
	key.bufferSeq = sessionPtr->bufferCount;
	fillTrackedSessionAndPushEvent(ctx, globalStatePtr, sessionPtr, &key, pidTgid, buf, bytesCount);
}

__attribute__((always_inline)) inline static void handleNoMoreData(
		struct pt_regs* ctx,
		struct DiscoveryGlobalState* globalStatePtr,
		struct DiscoveryAllSessionState* allSessionStatePtr,
		__u64 pidTgid,
		int fd) {
	struct DiscoveryTrackedSessionKey key = {.pid = pidTgidToPid(pidTgid), .fd = fd};
	// XXX: line below causes invalid bpf_context access off=335 size=1
	//const struct DiscoverySession* sessionPtr = (struct DiscoverySession*)bpf_map_lookup_elem(&trackedSessionsMap, &key);
	struct DiscoverySession deleteMeSession = {};
	const struct DiscoverySession* sessionPtr = &deleteMeSession;
	if (sessionPtr == NULL) {
		return;
	}

	struct DiscoveryEvent event = {};
	event.key.pid = key.pid;
	event.key.fd = fd;
	event.key.sessionID = sessionPtr->id;
	event.key.bufferSeq = sessionPtr->bufferCount;
	event.flags = DISCOVERY_FLAG_EVENT_DATA_END;
	// XXX: line below causes invalid bpf_context access off=335 size=1
	//pushEventToUserspace(ctx, globalStatePtr, &event);

	DEBUG_PRINTLN("Tracked session ended. (pid:`%d`, fd:`%d`, sessionID:`%d`)", event.key.pid, event.key.fd, event.key.sessionID);
	// XXX: line below causes invalid bpf_context access off=335 size=1
	//bpf_map_delete_elem(&trackedSessionsMap, &key);
}
