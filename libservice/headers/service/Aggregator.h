/*
 * Copyright 2024 Dynatrace LLC
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

#include "IpAddressChecker.h"
#include "Service.h"
#include "ebpfdiscoveryshared/Types.h"
#include "httpparser/HttpRequestParser.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

template <>
struct std::hash<std::pair<uint32_t, std::string>> {
	std::size_t operator()(const std::pair<uint32_t, std::string>& key) const {
		std::size_t seed = 0;
		boost::hash_combine(seed, key.first);
		boost::hash_combine(seed, key.second);
		return seed;
	}
};

namespace service {

struct DiscoverySessionMeta {
	DiscoverySockSourceIP sourceIP;
	__u32 pid;
	DiscoveryFlags flags;
};

class Aggregator {
private:
	using ServiceKey = std::pair<uint32_t, std::string>;
	using ServiceStorage = std::unordered_map<ServiceKey, Service>;

public:
	Aggregator(const service::IpAddressChecker& ipChecker);

	void clear();
	void newRequest(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta);
	std::vector<std::reference_wrapper<Service>> collectServices();

private:
	const IpAddressChecker& ipChecker;
	ServiceStorage services;
};

} // namespace service
