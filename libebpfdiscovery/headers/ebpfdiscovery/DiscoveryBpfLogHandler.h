// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "Config.h"
#include "DiscoveryBpf.h"
#include "ebpfdiscoveryshared/Types.h"

#include <bpf/libbpf.h>

#include <atomic>
#include <thread>

namespace ebpfdiscovery {

class DiscoveryBpfLogHandler {
public:
	DiscoveryBpfLogHandler(DiscoveryBpf discoveryBpf, const DiscoveryConfig config);
	DiscoveryBpfLogHandler(const DiscoveryBpfLogHandler&) = delete;
	DiscoveryBpfLogHandler(DiscoveryBpfLogHandler&&) = delete;
	DiscoveryBpfLogHandler& operator=(const DiscoveryBpfLogHandler&) = default;
	DiscoveryBpfLogHandler& operator=(DiscoveryBpfLogHandler&&) = delete;
	~DiscoveryBpfLogHandler() = default;

	void start();
	void stop();
	void wait();

	DiscoveryConfig config;
	DiscoveryBpf discoveryBpf;

private:
	void run();

	std::atomic<bool> running{false};
	std::atomic<bool> stopReceived{false};
	std::thread workerThread;

	struct perf_buffer* logPb;
};

} // namespace ebpfdiscovery
