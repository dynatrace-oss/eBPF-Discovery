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

#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include "DiscoveryBpf.h"

namespace ebpfdiscovery {

struct RawCounters {
	std::atomic<uint64_t> events{0};
	uint64_t eventErrors{};

	RawCounters() = default;
	RawCounters(const RawCounters& other);
	RawCounters& operator=(const RawCounters& other);
};

class PerfCounters {
	RawCounters curr;
	RawCounters prev;

	RawCounters calcDelta();

public:
	void addEventsCtr(uint64_t inc) {
		curr.events.fetch_add(inc, std::memory_order_relaxed);
	}
	void updateEventErrorsCtr(uint64_t val) {
		curr.eventErrors = val;
	}

	std::string printDiagnostics(const DiscoveryBpfFds discoveryBpf, const int savedBuffersMapKeySize, const int trackedSessionsMapKeySize);
};
} // namespace ebpfdiscovery
