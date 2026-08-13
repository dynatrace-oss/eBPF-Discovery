/*
* Copyright 2026 Dynatrace LLC
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

#include "ebpfdiscovery/Dvm.h"

#include "logging/Logger.h"

#include <boost/json.hpp>

#include <iostream>

namespace ebpfdiscovery {

Dvm::~Dvm() {
	unload();
}

void Dvm::outputToStdout(const std::vector<DvmLibraryLoad>& loads) {
	if (loads.empty()) {
		return;
	}
	boost::json::array arr;
	arr.reserve(loads.size());
	for (const auto& load : loads) {
		arr.push_back(boost::json::value_from(load));
	}
	const boost::json::object outJson{{"libraryLoads", std::move(arr)}};
	std::cout << boost::json::serialize(outJson) << std::endl;
}

void Dvm::collectAndOutput() {
	// No-op: BPF skeleton not yet wired in.
	// Future implementation will poll the ring buffer and call outputToStdout.
	LOG_DEBUG("DVM collectAndOutput called (no-op: BPF skeleton not yet available).");
	outputToStdout(libraryLoads);
	libraryLoads.clear();
}

void Dvm::load(const bpf_object_open_opts& /*openOpts*/) {
	// No-op: BPF skeleton not yet wired in.
	LOG_DEBUG("DVM load called (no-op: BPF skeleton not yet available).");
}

void Dvm::unload() {
	// No-op: nothing to clean up until the BPF skeleton is wired in.
}

} // namespace ebpfdiscovery
