// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "Service.h"
#include "ebpfdiscovery/IpAddressChecker.h"
#include "ebpfdiscoveryshared/Types.h"
#include "httpparser/HttpRequestParser.h"

#include <atomic>
#include <cstdint>
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
	Aggregator(ebpfdiscovery::IpAddressCheckerInerface& ipChecker);

	std::vector<Service> getServices();

	void newRequest(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta);

private:
	void updateServiceClientsNumber(Service& service, const DiscoverySessionMeta& meta);
	Service toService(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta);

	using ServiceKey = std::pair<uint32_t, std::string>;
	std::unordered_map<ServiceKey, Service> services;
	ebpfdiscovery::IpAddressCheckerInerface& ipChecker;

	std::atomic<bool> locked{false};
};

} // namespace service