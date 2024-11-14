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

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace service {

struct ArrayHasher {
	template<size_t N>
	std::size_t operator()(const std::array<uint8_t, N>& array) const {
		std::size_t hash = 0;
		for (auto element : array) {
			// The golden ratio hash is used to mix the bits to reduce collisions in std::unordered_map
			hash ^= std::hash<size_t>{}(element) + 0x9e3779b97f4a7c15ULL + (hash << 12) + (hash >> 4);
		}
		return hash;
	}
};

static constexpr uint8_t ipv6NetworkPrefixBytesLen = 6;
struct Service {
	uint32_t pid;
	std::string endpoint;
	std::string domain;
	std::string scheme;
	uint32_t internalClientsNumber{0u};
	uint32_t externalClientsNumber{0u};

	std::unordered_map<uint32_t, std::chrono::time_point<std::chrono::steady_clock>> detectedExternalIPv4_16Networks;
	std::unordered_map<uint32_t, std::chrono::time_point<std::chrono::steady_clock>> detectedExternalIPv4_24Networks;
	std::unordered_map<std::array<uint8_t, ipv6NetworkPrefixBytesLen>, std::chrono::time_point<std::chrono::steady_clock>, ArrayHasher> detectedExternalIPv6Networks;

	bool operator==(const Service& other) const {
		return pid == other.pid && endpoint == other.endpoint && domain == other.domain && scheme == other.scheme && internalClientsNumber == other.internalClientsNumber &&
				externalClientsNumber == other.externalClientsNumber &&
			   detectedExternalIPv4_16Networks == other.detectedExternalIPv4_16Networks &&
			   detectedExternalIPv4_24Networks == other.detectedExternalIPv4_24Networks && detectedExternalIPv6Networks == other.detectedExternalIPv6Networks;
	}
};

} // namespace service