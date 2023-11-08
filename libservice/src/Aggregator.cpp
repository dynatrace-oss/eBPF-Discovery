#include "service/Aggregator.h"
#include "ebpfdiscovery/StringFunctions.h"
#include "logging/Logger.h"

#include <arpa/inet.h>

namespace service {

Aggregator::Aggregator(ebpfdiscovery::IpAddressChecker& ipChecker) : ipChecker(ipChecker) {
	ipChecker.readNetworks();
}

void Aggregator::updateServiceClientsNumber(Service& service, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	std::string clientAddr;
	if (!request.xForwardedFor.empty()) {
		xForwardedForValueParser.parse(request.xForwardedFor);
		if (xForwardedForValueParser.result.addresses.empty()) {
			LOG_DEBUG("Malformed or empty X-Forwarded-For. (value: `{}`)", request.xForwardedFor);
			return;
		}
		clientAddr = xForwardedForValueParser.result.addresses.front();
		xForwardedForValueParser.result.clear();
	} else if (discoverySessionFlagsIsIPv4(meta.flags)) {
		clientAddr = ebpfdiscovery::ipv4ToString(meta.sourceIPData);
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		const auto v6Addr{ebpfdiscovery::ipv6ToString(meta.sourceIPData)};
		LOG_DEBUG("IPv6 not currently supported, request from src {} skipped", v6Addr);
		return;
	}

	in_addr_t clientAddrBinary;
	if (inet_pton(AF_INET, clientAddr.c_str(), &clientAddrBinary) != 1) {
		LOG_TRACE("Client address hasn't been parsed successfully");
		return;
	}

	if (ipChecker.isAddressExternalLocal(clientAddrBinary)) {
		++service.externalClientsNumber;
	} else {
		++service.internalClientsNumber;
	}
}

static std::string getEndpoint(const std::string& host, const std::string& url) {
	return host + url;
}

Service Aggregator::toService(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	Service service;
	service.pid = meta.pid;
	service.endpoint = getEndpoint(request.host, request.url);
	updateServiceClientsNumber(service, request, meta);
	return service;
}

void Aggregator::newRequest(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	const auto endpoint{getEndpoint(request.host, request.url)};
	ServiceKey key{meta.pid, endpoint};

	const auto it{services.find(key)};
	if (it != services.end()) {
		updateServiceClientsNumber((*it).second, request, meta);
		return;
	}
	auto newService{toService(request, meta)};

	std::lock_guard<std::mutex> lock(servicesMutex);
	services[key] = std::move(newService);
}

std::vector<Service> Aggregator::popServices() {
	std::lock_guard<std::mutex> lock(servicesMutex);

	std::vector<Service> ret;
	ret.reserve(services.size());

	for (auto s : services) {
		ret.emplace_back(s.second);
	}

	services.clear();
	return ret;
}

} // namespace service
