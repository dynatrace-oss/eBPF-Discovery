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
	DiscoveryBpf() = default;
	DiscoveryBpf(const DiscoveryBpf&) = delete;
	DiscoveryBpf& operator=(const DiscoveryBpf&) = delete;

	void load();
	void unload();

	DiscoveryBpfFds getFds();
	int getLogPerfBufFd();

private:
	bool coreEnsured{false};
	bpf_object_open_opts openOpts{0};

	discovery_bpf* skel{nullptr};
};

} // namespace ebpfdiscovery
