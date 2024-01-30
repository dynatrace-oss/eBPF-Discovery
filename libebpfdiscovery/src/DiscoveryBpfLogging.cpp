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

#include "ebpfdiscovery/DiscoveryBpfLogging.h"

#include <bpf/libbpf.h>

#include "ebpfdiscoveryshared/Types.h"
#include "logging/Logger.h"

namespace ebpfdiscovery::bpflogging {

constexpr int DISCOVERY_LOG_PERF_BUF_PAGES{64};

logging::LogLevel severityToLogLevel(const DiscoveryLogLevel severity) {
	switch (severity) {
	case DISCOVERY_LOG_LEVEL_TRACE:
		return logging::LogLevel::Trace;
	case DISCOVERY_LOG_LEVEL_DEBUG:
		return logging::LogLevel::Debug;
	case DISCOVERY_LOG_LEVEL_OFF:
		return logging::LogLevel::Off;
	}
	return logging::LogLevel::Off;
}

static void handleLogEvent(const DiscoveryLogEvent* event) {
	const logging::LogLevel level{severityToLogLevel(event->severity)};
	std::string message(DISCOVERY_LOG_MAX_MESSAGE_LENGTH, '\0');
	const int resultLength{snprintf(
			message.data(),
			message.size() + 1,
			event->format,
			event->args[0],
			event->args[1],
			event->args[2],
			event->args[3],
			event->args[4],
			event->args[5],
			event->args[6],
			event->args[7])};
	if (resultLength < 0) {
		LOG_DEBUG("Failed to format BPF log message.");
		return;
	}
	logging::Logger::getInstance().log(level, "[BPF] [{}] [{}] [{}] {}", event->timestamp, event->pidTgid >> 32, event->cpuId, message);
};

static void handlePerfLogEvent(void* ctx, int cpu, void* data, __u32 dataSize) {
	if (dataSize < sizeof(DiscoveryLogEvent)) {
		LOG_TRACE(
				"Received event on BPF log per buffer with unexpected data size. (received: {}, expected at least: {})",
				dataSize,
				sizeof(DiscoveryLogEvent));
		return;
	}

	handleLogEvent(static_cast<DiscoveryLogEvent*>(data));
}

static void handlePerfLogLostEvents(void* ctx, int cpu, __u64 lostEventsCount) {
	LOG_DEBUG("{} BPF log events have been lost.", lostEventsCount);
}

perf_buffer* setupLogging(int logPerfBufFd) {
	return perf_buffer__new(logPerfBufFd, DISCOVERY_LOG_PERF_BUF_PAGES, handlePerfLogEvent, handlePerfLogLostEvents, nullptr, nullptr);
}

int fetchAndLog(perf_buffer* logBuf) {
	return perf_buffer__consume(logBuf);
}

void closeLogging(perf_buffer* logBuf) {
	perf_buffer__free(logBuf);
}

} // namespace ebpfdiscovery::bpflogging
