// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/DiscoveryBpfLogHandler.h"

#include <bpf/libbpf.h>

#include "ebpfdiscoveryshared/Types.h"
#include "logging/Logger.h"

namespace ebpfdiscovery {

logging::LogLevel severityToLogLevel(const DiscoveryLogLevel severity) {
	switch (severity) {
	case DISCOVERY_LOG_LEVEL_TRACE:
		return logging::LogLevel::Trace;
	case DISCOVERY_LOG_LEVEL_DEBUG:
		return logging::LogLevel::Debug;
	case DISCOVERY_LOG_LEVEL_INFO:
		return logging::LogLevel::Info;
	case DISCOVERY_LOG_LEVEL_WARN:
		return logging::LogLevel::Warn;
	case DISCOVERY_LOG_LEVEL_ERROR:
		return logging::LogLevel::Err;
	case DISCOVERY_LOG_LEVEL_CRITICAL:
		return logging::LogLevel::Critical;
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
	LOG_DEBUG("{} BPF logging events have been lost.", lostEventsCount);
}

DiscoveryBpfLogHandler::DiscoveryBpfLogHandler(DiscoveryBpf discoveryBpf, const DiscoveryConfig config)
		: config(config), discoveryBpf(discoveryBpf) {
}

void DiscoveryBpfLogHandler::start() {
	if (running) {
		return;
	}
	running = true;

	logPb = perf_buffer__new(
			bpf_map__fd(discoveryBpf.skel->maps.logEventsPerfMap),
			config.logPerfBufferPages,
			handlePerfLogEvent,
			handlePerfLogLostEvents,
			nullptr,
			nullptr);
	if (logPb == nullptr) {
		throw std::runtime_error("Could not open perf buffer: " + std::to_string(-errno));
	}

	workerThread = std::thread([&]() { run(); });
}

void DiscoveryBpfLogHandler::run() {
	if (logPb == nullptr) {
		return;
	}

	LOG_TRACE("Discovery BPF log event handler loop is starting.");
	int err{0};
	while (!stopReceived) {
		err = perf_buffer__poll(logPb, config.logPerfPollInterval.count());
		if (err < 0 && errno != -EINTR) {
			LOG_ERROR("Error polling BPF perf buffer for logging: {}", std::strerror(-err));
			break;
		}
	}

	LOG_TRACE("Discovery BPF log event handler loop has finished running.");
	perf_buffer__free(logPb);
}

void DiscoveryBpfLogHandler::stop() {
	stopReceived = true;
}

void DiscoveryBpfLogHandler::wait() {
	if (workerThread.joinable()) {
		workerThread.join();
	}
}

} // namespace ebpfdiscovery
