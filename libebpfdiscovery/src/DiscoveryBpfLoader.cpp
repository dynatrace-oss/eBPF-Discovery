// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/DiscoveryBpfLoader.h"

#include "logging/Logger.h"

extern "C" {
#include "bpfload/btf_helpers.h"
}

namespace ebpfdiscovery {

DiscoveryBpfLoader::DiscoveryBpfLoader() {
}

DiscoveryBpfLoader::~DiscoveryBpfLoader() {
	unload();
}

void DiscoveryBpfLoader::load() {
	LOG_DEBUG("Loading BPF program.");
	LIBBPF_OPTS(bpf_object_open_opts, newOpenOpts);
	openOpts = newOpenOpts;

	if (int res{ensure_core_btf(&openOpts)}) {
		throw std::runtime_error("Failed to fetch necessary BTF for CO-RE: " + std::string(strerror(-res)));
	}

	skel = discovery_bpf__open_opts(&openOpts);
	if (skel == nullptr) {
		throw std::runtime_error("Failed to open BPF object.");
	}

	if (int res{discovery_bpf__load(skel)}) {
		throw std::runtime_error("Failed to load BPF object: " + std::to_string(res));
	}

	if (int res{discovery_bpf__attach(skel)}) {
		throw std::runtime_error("Failed to attach BPF object: " + std::to_string(res));
	}

	loaded = true;
}

void DiscoveryBpfLoader::unload() noexcept {
	loaded = false;
	if (skel != nullptr) {
		discovery_bpf__destroy(skel);
	}
	cleanup_core_btf(&openOpts);
}

bool DiscoveryBpfLoader::isLoaded() noexcept {
	return skel != nullptr && loaded;
}

DiscoveryBpf DiscoveryBpfLoader::get() {
	return DiscoveryBpf(skel);
}

} // namespace ebpfdiscovery
