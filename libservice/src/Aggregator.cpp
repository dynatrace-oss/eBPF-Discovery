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

static void incrementServiceClientsNumber(IpAddressChecker& ipChecker, Service& service, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	std::string clientAddr;
	if (!request.xForwardedFor.empty()) {
		clientAddr = request.xForwardedFor.front();
	} else if (discoverySessionFlagsIsIPv4(meta.flags)) {
		clientAddr = ipv4ToString(meta.sourceIPData);
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		const auto v6Addr{inet_addr(ipv6ToString(meta.sourceIPData).c_str())};
		LOG_DEBUG("IPv6 not currently supported, request from src {} skipped", v6Addr);
		return;
	}

	in_addr_t clientAddrBinary;
	if (inet_pton(AF_INET, clientAddr.c_str(), &clientAddrBinary) != 1) {
		LOG_TRACE("Cannot parse X-Forwarded-For client address: {}", clientAddr);
		return;
	}

	if (ipChecker.isAddressExternalLocal(clientAddrBinary)) {
		++service.externalClientsNumber;
	} else {
		++service.internalClientsNumber;
	}
}

static Service toService(IpAddressChecker& ipChecker, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	Service service;
	service.pid = meta.pid;
	service.endpoint = getEndpoint(request.host, request.url);
	incrementServiceClientsNumber(ipChecker, service, request, meta);
	return service;
}

Aggregator::Aggregator(IpAddressChecker& ipChecker) : ipChecker(ipChecker) {
	ipChecker.readNetworks();
}

void Aggregator::clear() {
	services.clear();
}

void Aggregator::newRequest(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	const auto endpoint{getEndpoint(request.host, request.url)};
	ServiceKey key{meta.pid, endpoint};

	const auto it{services.find(key)};
	if (it != services.end()) {
		incrementServiceClientsNumber(ipChecker, it->second, request, meta);
		return;
	}
	auto newService{toService(ipChecker, request, meta)};

	services[key] = std::move(newService);
}

std::vector<std::reference_wrapper<Service>> Aggregator::collectServices() {
	std::vector<std::reference_wrapper<Service>> servicesVec;
	servicesVec.reserve(services.size());

	for (auto& pair : services) {
		servicesVec.push_back(pair.second);
	}

	return servicesVec;
}

} // namespace service
