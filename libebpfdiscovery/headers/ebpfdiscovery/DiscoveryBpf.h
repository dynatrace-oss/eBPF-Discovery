// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "discovery.skel.h"

#include <string>

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
	void attachNetworkingProbes();
	void attachLibSSLProbes();

	void attachKprobe(bpf_link** link, bpf_program* prog, const std::string& funcName);
	void attachKretprobe(bpf_link** link, bpf_program* prog, const std::string& funcName);
	void attachUprobeToLibFunc(bpf_link** link, bpf_program* prog, const std::string& libName, const std::string& funcName);
	void attachUretprobeToLibFunc(bpf_link** link, bpf_program* prog, const std::string& libName, const std::string& funcName);

	bool coreEnsured{false};
	bpf_object_open_opts openOpts{0};

	discovery_bpf* skel{nullptr};
};

} // namespace ebpfdiscovery
