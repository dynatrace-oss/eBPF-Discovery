// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ebpfdiscovery/DiscoveryBpf.h"

#include "discovery.skel.h"

#include <atomic>

namespace ebpfdiscovery {
class DiscoveryBpfLoader {
public:
	DiscoveryBpfLoader();
	DiscoveryBpfLoader(const DiscoveryBpfLoader&) = delete;
	DiscoveryBpfLoader& operator=(const DiscoveryBpfLoader&) = delete;
	DiscoveryBpfLoader(DiscoveryBpfLoader&&) = default;
	DiscoveryBpfLoader& operator=(DiscoveryBpfLoader&&) = default;
	~DiscoveryBpfLoader();

	void load();
	void unload() noexcept;
	bool isLoaded() noexcept;

	DiscoveryBpf get();

private:
	std::atomic<bool> loaded;
	bpf_object_open_opts openOpts;
	discovery_bpf* skel;
};

} // namespace ebpfdiscovery
