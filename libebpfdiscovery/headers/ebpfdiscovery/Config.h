// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>
#include <string>

namespace ebpfdiscovery {

struct DiscoveryConfig {
	std::chrono::milliseconds eventQueuePollInterval{std::chrono::milliseconds(250)};
	std::chrono::milliseconds logPerfPollInterval{std::chrono::milliseconds(250)};
	size_t logPerfBufferPages{1024};
};

} // namespace ebpfdiscovery
