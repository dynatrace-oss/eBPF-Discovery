/*
* Copyright 2026 Dynatrace LLC
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

#include "ebpfdiscovery/ServiceDetectionTask.h"
#include "ebpfdiscovery/DiscoveryBpfLogging.h"

namespace ebpfdiscovery {

void ServiceDetectionTask::PerfBufferDeleter::operator()(perf_buffer* buffer) {
	bpflogging::fetchAndLog(buffer);
}

void ServiceDetectionTask::start(const bpf_object_open_opts& loadOptions, bool enableNetworkCounters, std::chrono::seconds interval, logging::LogLevel logLevel)  {
	discoveryBpf.load(loadOptions);

	instance = std::make_unique<Discovery>(discoveryBpf.getFds(), enableNetworkCounters);
	if (!instance) {
		throw std::runtime_error("Failed to allocated memory for DiscoveryBpf instance");
	}
	instance->init();

	const int logPerfBufFd{discoveryBpf.getLogPerfBufFd()};

	logBuf.reset(bpflogging::setupLogging(logPerfBufFd));
	if (logBuf == nullptr) {
		throw std::runtime_error(fmt::format("Could not open perf buffer for Discovery BPF logging: {}.", std::strerror(errno)));
	}

	auto eventQueuePollInterval{std::chrono::milliseconds(250)};
	featchAndHandleEventsFuture = startAsync(std::chrono::milliseconds{eventQueuePollInterval}, [this]() {
		auto ret{instance->fetchAndHandleEvents()};
		if (ret != 0) {
			LOG_CRITICAL("Failed to fetch and handle Discovery BPF events: {}.", std::strerror(-ret));
			stop();
		}
	});

	if (enableNetworkCounters) {
		auto networkCountersCleaningInterval{std::chrono::minutes(1)};
		networkCountersCleaningFuture = startAsync(std::chrono::milliseconds{networkCountersCleaningInterval}, [this]() {
			instance->networkCountersCleaning();
		});
	}

	outputServicesToStdoutFuture = startAsync(std::chrono::milliseconds{interval}, [this]() {
		instance->outputServicesToStdout();
	});

	auto logBufFetchInterval{std::chrono::milliseconds(250)};
	logBpfLoggingFuture = setupBpfLogging(logLevel, logBufFetchInterval);
}

ServiceDetectionTask::~ServiceDetectionTask() {
	shutdown();
}

void ServiceDetectionTask::shutdown() {
	stop();
	waitForFinish();
	logBuf.reset();
	instance.reset();
	discoveryBpf.unload();
}

void ServiceDetectionTask::waitForFinish() {
	if(outputServicesToStdoutFuture.valid()) {
		outputServicesToStdoutFuture.wait();
	}
	if(logBpfLoggingFuture.valid()) {
		logBpfLoggingFuture.wait();
	}
	if(featchAndHandleEventsFuture.valid()) {
		featchAndHandleEventsFuture.wait();
	}
	if(networkCountersCleaningFuture.valid()) {
		networkCountersCleaningFuture.wait();
	}
}

std::future<void> ServiceDetectionTask::setupBpfLogging(logging::LogLevel logLevel, std::chrono::milliseconds logBufFetchInterval){
	if (logLevel <= logging::LogLevel::Debug) {
		LOG_DEBUG("Handling of Discovery BPF logging is enabled.");
		return startAsync(logBufFetchInterval, [this]() {
			auto ret{bpflogging::fetchAndLog(logBuf.get())};
			if (ret != 0) {
				LOG_CRITICAL("Failed to fetch and handle Discovery BPF logging: {}.", std::strerror(-ret));
				stop();
			}
		});
	}
	return {};
}

}