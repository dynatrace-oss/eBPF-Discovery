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
#include <stdexcept>

#include "../headers/ebpfdiscovery/BpfOptions.h"
#include "logging/Logger.h"

extern "C" {
#include "../../third_party/bcc/libbpf-tools/btf_helpers.h"
}

namespace ebpfdiscovery {

BpfOptions::~BpfOptions() {
	release();
}

void BpfOptions::acquire() {
	{
		LIBBPF_OPTS(bpf_object_open_opts, newOpenOpts);
		openOpts = newOpenOpts;
	}

	LOG_TRACE("Fetching BTF for CO-RE.");
	if (const auto res{ensure_core_btf(&openOpts)}) {
		throw std::runtime_error("Failed to fetch necessary BTF for CO-RE: " + std::string(strerror(-res)));
	}
	coreEnsured = true;
}

void BpfOptions::release() {
	if (coreEnsured) {
		cleanup_core_btf(&openOpts);
		coreEnsured = false;
	}
}

const bpf_object_open_opts& BpfOptions::getOpenOpts() const{
	return openOpts;
}

}
