// SPDX-License-Identifier: Apache-2.0

#include "ebpfdiscovery/Config.h"
#include "ebpfdiscoveryproto/example.pb.h"

namespace ebpfdiscovery {

DiscoveryConfig::DiscoveryConfig() noexcept : eventQueuePollInterval(std::chrono::milliseconds(250)) {
}

} // namespace ebpfdiscovery
