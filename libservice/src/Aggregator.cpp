// SPDX-License-Identifier: Apache-2.0
#include "service/Aggregator.h"

#include "logging/Logger.h"
#include "service/IpAddress.h"
#include "service/IpAddressChecker.h"

#include <arpa/inet.h>

namespace service {

static std::string getEndpoint(const std::string& host, const std::string& url) {
	return host + url;
}

static void incrementServiceClientsNumber(IpAddressChecker& ipChecker, Service& service, const DiscoverySessionMeta& meta) {
	if (discoverySessionFlagsIsIPv4(meta.flags)) {
		const auto v4Addr{inet_addr(ipv4ToString(meta.sourceIPData).c_str())};
		if (ipChecker.isAddressExternalLocal(v4Addr)) {
			++service.externalClientsNumber;
		} else {
			++service.internalClientsNumber;
		}
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		const auto v6Addr{inet_addr(ipv6ToString(meta.sourceIPData).c_str())};
		LOG_DEBUG("IPv6 not currently supported, request from src {} skipped", v6Addr);
	} else {
		++service.externalClientsNumber;
	}
}

static Service toService(IpAddressChecker& ipChecker, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	Service service;
	service.pid = meta.pid;
	service.endpoint = getEndpoint(request.host, request.url);
	incrementServiceClientsNumber(ipChecker, service, meta);
	return service;
}

Aggregator::Aggregator(IpAddressChecker& ipChecker) : ipChecker(ipChecker) {
	ipChecker.readNetworks();
}

void Aggregator::clear() {
	services.clear();
}

Aggregator::ServiceStorage::iterator Aggregator::begin() {
	return services.begin();
}

Aggregator::ServiceStorage::const_iterator Aggregator::begin() const {
	return services.begin();
}

Aggregator::ServiceStorage::iterator Aggregator::end() {
	return services.end();
}

Aggregator::ServiceStorage::const_iterator Aggregator::end() const {
	return services.end();
}

void Aggregator::newRequest(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	const auto endpoint{getEndpoint(request.host, request.url)};
	ServiceKey key{meta.pid, endpoint};

	const auto it{services.find(key)};
	if (it != services.end()) {
		incrementServiceClientsNumber(ipChecker, it->second, meta);
		return;
	}
	auto newService{toService(ipChecker, request, meta)};

	services[key] = std::move(newService);
}

std::vector<Service> Aggregator::getServices() {
	std::vector<Service> servicesVec;
	servicesVec.reserve(services.size());

	for (const auto& pair : services) {
		servicesVec.push_back(pair.second);
	}

	return servicesVec;
}

std::vector<std::reference_wrapper<Service>> Aggregator::getServicesRef() {
	std::vector<std::reference_wrapper<Service>> servicesVec;
	servicesVec.reserve(services.size());

	for (auto& pair : services) {
		servicesVec.push_back(pair.second);
	}

	return servicesVec;
}

} // namespace service
