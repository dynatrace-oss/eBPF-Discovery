// SPDX-License-Identifier: Apache-2.0
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
