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

#include "ebpfdiscovery/PerfCounters.h"
#include "ebpfdiscoveryshared/Constants.h"
#include <bpf/bpf.h>
#include <cerrno>
#include <fmt/format.h>
#include <vector>

namespace ebpfdiscovery {

RawCounters::RawCounters(const RawCounters& other) : events{other.events.load(std::memory_order_relaxed)}, eventErrors{other.eventErrors} {
}

RawCounters& RawCounters::operator=(const RawCounters& other) {
	if (this != &other) {
		events.store(other.events.load(std::memory_order_relaxed), std::memory_order_relaxed);
		eventErrors = other.eventErrors;
	}
	return *this;
}

RawCounters PerfCounters::calcDelta() {
	RawCounters delta{};
	RawCounters snapshot = curr;

	delta.events = snapshot.events.load(std::memory_order_relaxed) - prev.events.load(std::memory_order_relaxed);
	delta.eventErrors = snapshot.eventErrors - prev.eventErrors;
	prev = snapshot;
	return delta;
}

static long countMapElements(int mapFd, size_t keySize) {
	std::vector<uint8_t> key(keySize), next(keySize);
	long count = 0;

	int err = bpf_map_get_next_key(mapFd, nullptr, next.data());
	for (int i = 0; i < 2 * DISCOVERY_MAX_SESSIONS && err == 0; i++) {
		++count;
		key.swap(next);
		err = bpf_map_get_next_key(mapFd, key.data(), next.data());
	}
	return (errno == ENOENT) ? count : -1;
}

std::string PerfCounters::printDiagnostics(
		const DiscoveryBpfFds fds, const int savedBuffersMapKeySize, const int trackedSessionsMapKeySize) {
	RawCounters delta = calcDelta();
	int32_t savedBuffersMapSize = countMapElements(fds.savedBuffersMap, savedBuffersMapKeySize);
	int32_t trackedSessionsMapSize = countMapElements(fds.trackedSessionsMap, trackedSessionsMapKeySize);

	return fmt::format(
			"eventsCtr={} pushEventErrorsCtr={} savedBuffersMapSize={} trackedSessionsMapSize={}",
			delta.events.load(std::memory_order_relaxed),
			delta.eventErrors,
			savedBuffersMapSize,
			trackedSessionsMapSize);
}
} // namespace ebpfdiscovery
