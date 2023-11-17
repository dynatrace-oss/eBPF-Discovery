// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "discovery.skel.h"

namespace ebpfdiscovery {

struct DiscoveryBpfFds {
	int globalStateMap;
	int eventsToUserspaceQueueMap;
	int savedBuffersMap;
	int trackedSessionsMap;
};

class DiscoveryBpf {
public:
	DiscoveryBpf();
	DiscoveryBpf(const DiscoveryBpf&) = delete;
	DiscoveryBpf& operator=(const DiscoveryBpf&) = delete;
	~DiscoveryBpf();

	bool isRunning() noexcept;
	void load();
	void unload() noexcept;

	DiscoveryBpfFds getFds();

private:
	void resetState() noexcept;

	bool coreEnsured{false};
	bool opened{false};
	bool attached{false};
	bpf_object_open_opts openOpts{0};

	discovery_bpf* skel{nullptr};
};

} // namespace ebpfdiscovery
