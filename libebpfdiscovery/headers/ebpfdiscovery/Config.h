// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>
#include <string>

namespace ebpfdiscovery {

struct DiscoveryConfig {
	std::chrono::milliseconds eventQueuePollInterval;

	DiscoveryConfig() noexcept;
};

} // namespace ebpfdiscovery
