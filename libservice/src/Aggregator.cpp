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
		throw std::runtime_error("Couldn't parse IPv4 client address");
	}
	return ipChecker.isV4AddressExternal(clientAddrBinary);
}

static bool isIpv6ClientExternal(const IpAddressChecker& ipChecker, const std::string& addr) {
	in6_addr clientAddrBinary{};
	if (inet_pton(AF_INET6, addr.c_str(), &clientAddrBinary) != 1) {
		throw std::runtime_error("Couldn't parse IPv6 client address");
	}
	return ipChecker.isV6AddressExternal(clientAddrBinary);
}

static bool isClientExternal(const IpAddressChecker& ipChecker, const std::string& addr, bool isIpv6) {
	return isIpv6 ? isIpv6ClientExternal(ipChecker, addr) : isIpv4ClientExternal(ipChecker, addr);
}

static bool isClientExternal(const IpAddressChecker& ipChecker, const std::string& addr) {
	bool isPossiblyIpv6{std::count(addr.begin(), addr.end(), ':') >= 2};
	return isClientExternal(ipChecker, addr, isPossiblyIpv6);
}

static void incrementServiceClientsNumber(
		const IpAddressChecker& ipChecker, Service& service, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	bool isExternal{false};
	std::string clientAddr;
	try {
		if (!request.xForwardedFor.empty()) {
			clientAddr = request.xForwardedFor.front();
			isExternal = isClientExternal(ipChecker, clientAddr);
		} else if (discoverySessionFlagsIsIPv4(meta.flags)) {
			clientAddr = ipv4ToString(meta.sourceIPData);
			isExternal = isClientExternal(ipChecker, clientAddr, false);
		} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
			clientAddr = ipv6ToString(meta.sourceIPData);
			isExternal = isClientExternal(ipChecker, clientAddr, true);
		} else {
			return;
		}
	} catch (const std::runtime_error& e) {
		LOG_TRACE("Couldn't determine if the client is external: {} (client address: {})", e.what(), clientAddr);
	}

	if (isExternal) {
		++service.externalClientsNumber;
	} else {
		++service.internalClientsNumber;
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
