#include "service/Aggregator.h"
#include "ebpfdiscovery/StringFunctions.h"
#include "logging/Logger.h"

#include <arpa/inet.h>

namespace service {

Aggregator::Aggregator(ebpfdiscovery::IpAddressCheckerInerface& ipChecker) : ipChecker(ipChecker) {
}

void Aggregator::updateServiceClientsNumber(Service& service, const DiscoverySessionMeta& meta) {
	if (discoverySessionFlagsIsIPv4(meta.flags)) {
		auto v4Addr = inet_addr(ebpfdiscovery::ipv4ToString(meta.sourceIPData).c_str());
		if (ipChecker.isAddressExternalLocal(v4Addr)) {
			++service.externalClientsNumber;
		} else {
			++service.internalClientsNumber;
		}
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		auto v6Addr = inet_addr(ebpfdiscovery::ipv6ToString(meta.sourceIPData).c_str());
		LOG_DEBUG("IPv6 not currently supported, request from src {} skipped", v6Addr);
	} else {
		++service.externalClientsNumber;
	}
}

static std::string getEndpoint(const std::string& host, const std::string& url) {
	return host + url;
}

Service Aggregator::toService(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	Service service;
	service.pid = meta.pid;
	service.endpoint = getEndpoint(request.host, request.url);
	updateServiceClientsNumber(service, meta);
	return service;
}

void Aggregator::newRequest(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	if (locked)
		return;

	auto endpoint{getEndpoint(request.host, request.url)};
	ServiceKey key{meta.pid, endpoint};

	auto it{services.find(key)};
	if (it != services.end()) {
		updateServiceClientsNumber((*it).second, meta);
		return;
	}
	auto newService = toService(request, meta);
	services[key] = std::move(newService);
}

std::vector<Service> Aggregator::getServices() {
	locked = true;

	std::vector<Service> ret;
	ret.reserve(services.size());

	for (auto s : services) {
		ret.emplace_back(s.second);
	}

	services.clear();
	locked = false;
	return ret;
}

} // namespace service