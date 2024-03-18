/*
 * Copyright 2023 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
	void attachSyscallProbes();
	void attachLibSSLProbes();

	bool coreEnsured{false};
	bpf_object_open_opts openOpts{0};

	discovery_bpf* skel{nullptr};
};

} // namespace ebpfdiscovery
