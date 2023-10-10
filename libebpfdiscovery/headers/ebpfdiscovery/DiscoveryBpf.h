// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "discovery.skel.h"

namespace ebpfdiscovery {

class DiscoveryBpf {
public:
	DiscoveryBpf(discovery_bpf* skel);
	DiscoveryBpf(const DiscoveryBpf&) = default;
	DiscoveryBpf& operator=(const DiscoveryBpf&) = default;
	DiscoveryBpf(DiscoveryBpf&&) = default;
	DiscoveryBpf& operator=(DiscoveryBpf&&) = default;
	~DiscoveryBpf() = default;

	discovery_bpf* skel;
};

} // namespace ebpfdiscovery
