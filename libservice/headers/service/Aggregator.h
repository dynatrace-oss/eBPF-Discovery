// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "Service.h"
#include "ebpfdiscovery/IpAddressChecker.h"
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
public:
	Aggregator(ebpfdiscovery::IpAddressChecker& ipChecker);

	std::vector<Service> popServices();

	void newRequest(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta);

private:
	void updateServiceClientsNumber(Service& service, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta);
	Service toService(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta);

	using ServiceKey = std::pair<uint32_t, std::string>;

	ebpfdiscovery::IpAddressChecker& ipChecker;

	std::unordered_map<ServiceKey, Service> services;
	std::mutex servicesMutex;
};

} // namespace service
