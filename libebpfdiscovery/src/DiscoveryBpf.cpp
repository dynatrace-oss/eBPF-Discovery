// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/DiscoveryBpf.h"

#include "logging/Logger.h"

extern "C" {
#include "bpfload/btf_helpers.h"
}

namespace ebpfdiscovery {

void DiscoveryBpf::load() {
	LOG_DEBUG("Loading BPF program.");

	{
		LIBBPF_OPTS(bpf_object_open_opts, newOpenOpts);
		openOpts = newOpenOpts;
	}

	if (const auto res{ensure_core_btf(&openOpts)}) {
		throw std::runtime_error("Failed to fetch necessary BTF for CO-RE: " + std::string(strerror(-res)));
	}
	coreEnsured = true;

	skel = discovery_bpf__open_opts(&openOpts);
	if (skel == nullptr) {
		throw std::runtime_error("Failed to open BPF object.");
	}

	if (const auto res{discovery_bpf__load(skel)}) {
		throw std::runtime_error("Failed to load BPF object: " + std::to_string(res));
	}

	if (const auto res{discovery_bpf__attach(skel)}) {
		throw std::runtime_error("Failed to attach BPF object: " + std::to_string(res));
	}
}

void DiscoveryBpf::unload() {
	if (skel != nullptr) {
		discovery_bpf__destroy(skel);
		skel = nullptr;
	}

	if (coreEnsured) {
		cleanup_core_btf(&openOpts);
		coreEnsured = false;
	}
}

DiscoveryBpfFds DiscoveryBpf::getFds() {
	return {
			.globalStateMap = bpf_map__fd(skel->maps.globalStateMap),
			.eventsToUserspaceQueueMap = bpf_map__fd(skel->maps.eventsToUserspaceQueueMap),
			.savedBuffersMap = bpf_map__fd(skel->maps.savedBuffersMap),
			.trackedSessionsMap = bpf_map__fd(skel->maps.trackedSessionsMap),
	};
}

int DiscoveryBpf::getLogPerfBufFd() {
	return bpf_map__fd(skel->maps.logEventsPerfMap);
}

} // namespace ebpfdiscovery
