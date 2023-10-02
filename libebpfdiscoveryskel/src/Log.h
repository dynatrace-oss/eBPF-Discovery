#pragma once
// SPDX-License-Identifier: GPL-2.0

#include "Config.h"
#include "DataFunctions.h"
#include "ebpfdiscoveryshared/Constants.h"
#include "ebpfdiscoveryshared/Types.h"

#include "vmlinux.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} logEventsPerfMap SEC(".maps");

#define DEBUG_PRINTLN(fmt, ...)                                  \
	{                                                            \
		char newFmt[] = "[ebpf-discovery] " fmt "\n";            \
		bpf_trace_printk(newFmt, sizeof(newFmt), ##__VA_ARGS__); \
	}

__attribute__((always_inline)) inline static int sendDiscoveryLogEvent(struct pt_regs* ctx, struct DiscoveryLogEvent* logEventPtr) {
	return bpf_perf_event_output(ctx, &logEventsPerfMap, BPF_F_CURRENT_CPU, logEventPtr, sizeof(*logEventPtr));
}

__attribute__((always_inline)) inline static enum DiscoveryLogLevel getDiscoveryLogLevel() {
	struct DiscoveryConfig* configPtr = getDiscoveryConfig();
	if (configPtr == NULL) {
		return DISCOVERY_LOG_LEVEL_OFF;
	}
	return configPtr->logLevel;
}

__attribute__((always_inline)) inline static int discoveryLog(
		struct pt_regs* ctx, enum DiscoveryLogLevel severity, const char* fmt, size_t dataLength, const char* data) {
	if (severity < getDiscoveryLogLevel()) {
		return 0;
	}

	struct DiscoveryLogEvent logEvent = {.severity = severity};
	logEvent.timestamp = bpf_ktime_get_ns();
	logEvent.cpuId = bpf_get_smp_processor_id();
	logEvent.pidTgid = bpf_get_current_pid_tgid();

	dataStringFormat((char*)logEvent.message.str, sizeof(logEvent.message.str), fmt, dataLength, data);
	return sendDiscoveryLogEvent(ctx, &logEvent);
}

#define CHOOSE_MACRO(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, NAME, ...) NAME
#define COUNT_ARGUMENTS(...) CHOOSE_MACRO(__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define DISCOVERY_LOG(ctx, severity, fmt, ...)                    \
	{                                                             \
		int argsCount = COUNT_ARGUMENTS(NULL, __VA_ARGS__);       \
		if (argsCount > 0) {                                      \
			char data[] = {__VA_ARGS__};                          \
			discoveryLog(ctx, severity, fmt, sizeof(data), data); \
		} else {                                                  \
			discoveryLog(ctx, severity, fmt, 0, NULL);            \
		}                                                         \
	}

#define LOG_TRACE(ctx, fmt, ...) DISCOVERY_LOG(ctx, DISCOVERY_LOG_LEVEL_TRACE, fmt, __VA_ARGS__)
// #define LOG_DEBUG(ctx, fmt, ...) DISCOVERY_LOG(ctx, BPF_LOG_LEVEL_DEBUG, fmt, __VA_ARGS__)
#define LOG_INFO(ctx, fmt, ...) DISCOVERY_LOG(ctx, DISCOVERY_LOG_LEVEL_INFO, fmt, __VA_ARGS__)
// #define LOG_WARN(ctx, fmt, ...) DISCOVERY_LOG(ctx, BPF_LOG_LEVEL_WARN, fmt, __VA_ARGS__)
// #define LOG_ERROR(ctx, fmt, ...) DISCOVERY_LOG(ctx, BPF_LOG_LEVEL_ERROR, fmt, __VA_ARGS__)
// #define LOG_CRITICAL(ctx, fmt, ...) DISCOVERY_LOG(ctx, BPF_LOG_LEVEL_CRITICAL, fmt, __VA_ARGS__)
