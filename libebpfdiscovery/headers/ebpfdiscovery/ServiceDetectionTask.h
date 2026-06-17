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

#pragma once
#include "AsyncTask.h"
#include "Discovery.h"
#include "DiscoveryBpf.h"
#include "logging/Logger.h"

namespace ebpfdiscovery {

class ServiceDetectionTask : public AsyncTask {
public:
	using AsyncTask::stop;

	~ServiceDetectionTask() override;

	void start(const bpf_object_open_opts& loadOptions, bool enableNetworkCounters, std::chrono::seconds interval, logging::LogLevel logLevel);
	void shutdown();
	void waitForFinish();
private:
	struct PerfBufferDeleter {
		void operator()(perf_buffer* buffer);
	};
	std::future<void> setupBpfLogging(logging::LogLevel logLevel, std::chrono::milliseconds logBufFetchInterval);

	DiscoveryBpf discoveryBpf;
	std::unique_ptr<Discovery> instance{nullptr};

	std::future<void> networkCountersCleaningFuture{};
	std::future<void> featchAndHandleEventsFuture{};
	std::future<void> outputServicesToStdoutFuture{};
	std::future<void> logBpfLoggingFuture{};
	std::unique_ptr<perf_buffer, PerfBufferDeleter> logBuf{nullptr};
};

}