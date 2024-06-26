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

#include "Config.h"
#include "DataFunctions.h"
#include "ebpfdiscoveryshared/Constants.h"
#include "ebpfdiscoveryshared/Types.h"

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} logEventsPerfMap SEC(".maps");

__attribute__((always_inline)) inline static int sendDiscoveryLogEvent(struct pt_regs* ctx, struct DiscoveryLogEvent* logEventPtr) {
	return bpf_perf_event_output(ctx, &logEventsPerfMap, BPF_F_CURRENT_CPU, logEventPtr, sizeof(struct DiscoveryLogEvent));
}

__attribute__((always_inline)) inline static enum DiscoveryLogLevel getDiscoveryLogLevel() {
	const struct DiscoveryConfig* configPtr = getDiscoveryConfig();
	if (configPtr == NULL) {
		return DISCOVERY_LOG_LEVEL_OFF;
	}
	return (configPtr->logLevel > 0) ? configPtr->logLevel : DISCOVERY_LOG_LEVEL_OFF;
}

__attribute__((always_inline)) inline static int discoveryLog(
		struct pt_regs* ctx, enum DiscoveryLogLevel severity, const char* fmt, size_t argsCount, const DiscoveryLogEventArg* args) {
	if (severity < getDiscoveryLogLevel()) {
		return 0;
	}

	struct DiscoveryLogEvent logEvent = {.severity = severity};
	logEvent.timestamp = bpf_ktime_get_ns();
	logEvent.cpuId = bpf_get_smp_processor_id();
	logEvent.pidTgid = bpf_get_current_pid_tgid();
	dataCopyString(fmt, logEvent.format, DISCOVERY_LOG_MAX_FORMAT_LENGTH);

	if (argsCount > 0) {
		for (size_t i = 0; i < argsCount && i < DISCOVERY_LOG_MAX_ARGS_COUNT; ++i) {
			logEvent.args[i] = args[i];
		}
	}

	return sendDiscoveryLogEvent(ctx, &logEvent);
}

#define CHOOSE_MACRO(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, NAME, ...) NAME
#define COUNT_ARGUMENTS(...) CHOOSE_MACRO(__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define DISCOVERY_LOG(ctx, severity, fmt, ...)                 \
	{                                                          \
		int argsCount = COUNT_ARGUMENTS(NULL, __VA_ARGS__);    \
		if (argsCount > 0) {                                   \
			const DiscoveryLogEventArg args[] = {__VA_ARGS__}; \
			discoveryLog(ctx, severity, fmt, argsCount, args); \
		} else {                                               \
			discoveryLog(ctx, severity, fmt, 0, NULL);         \
		}                                                      \
	}

#define LOG_TRACE(ctx, fmt, ...) DISCOVERY_LOG(ctx, DISCOVERY_LOG_LEVEL_TRACE, fmt, __VA_ARGS__)
#define LOG_DEBUG(ctx, fmt, ...) DISCOVERY_LOG(ctx, DISCOVERY_LOG_LEVEL_DEBUG, fmt, __VA_ARGS__)
