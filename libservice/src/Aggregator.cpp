// SPDX-License-Identifier: Apache-2.0
#include "service/Aggregator.h"

#include "logging/Logger.h"
#include "service/IpAddress.h"
#include "service/IpAddressNetlinkChecker.h"

#include <arpa/inet.h>

namespace service {

static std::string getEndpoint(const std::string& host, const std::string& url) {
	return host + url;
}

static bool isIpv4ClientExternal(const IpAddressChecker& ipChecker, const std::string& addr) {
	in_addr_t clientAddrBinary;
	if (inet_pton(AF_INET, addr.c_str(), &clientAddrBinary) != 1) {
		return true;
	}
	return ipChecker.isV4AddressExternal(clientAddrBinary);
}

static bool isIpv6ClientExternal(const IpAddressChecker& ipChecker, const std::string& addr) {
	in6_addr clientAddrBinary{};
	if (inet_pton(AF_INET6, addr.c_str(), &clientAddrBinary) != 1) {
		return true;
	}
	return ipChecker.isV6AddressExternal(clientAddrBinary);
}

static bool isClientExternal(const IpAddressChecker& ipChecker, const std::string& addr) {
	bool isPossiblyIpv6{addr.find(':') != std::string::npos};
	return isPossiblyIpv6 ? isIpv6ClientExternal(ipChecker, addr) : isIpv4ClientExternal(ipChecker, addr);
}

static bool isClientExternal(const IpAddressChecker& ipChecker, const std::string& addr, bool isIpV6) {
	return isIpV6 ? isIpv6ClientExternal(ipChecker, addr) : isIpv4ClientExternal(ipChecker, addr);
}

static void incrementServiceClientsNumber(
		const IpAddressChecker& ipChecker, Service& service, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	bool isExternal{false};
	if (!request.xForwardedFor.empty()) {
		isExternal = isClientExternal(ipChecker, request.xForwardedFor.front());
	} else if (discoverySessionFlagsIsIPv4(meta.flags)) {
		isExternal = isClientExternal(ipChecker, ipv4ToString(meta.sourceIPData), false);
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		isExternal = isClientExternal(ipChecker, ipv6ToString(meta.sourceIPData), true);
	} else {
		return;
	}

	try {
		if (isExternal) {
			++service.externalClientsNumber;
		} else {
			++service.internalClientsNumber;
		}
	} catch (const std::runtime_error& e) {
		LOG_TRACE(e.what());
		return;
	}
}

static Service toService(const IpAddressChecker& ipChecker, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	Service service;
	service.pid = meta.pid;
	service.endpoint = getEndpoint(request.host, request.url);
	incrementServiceClientsNumber(ipChecker, service, request, meta);
	return service;
}

Aggregator::Aggregator(const IpAddressChecker& ipChecker) : ipChecker{ipChecker} {
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
