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
#include "service/IpAddressCheckerImpl.h"

#include <arpa/inet.h>

namespace service {

static std::string getEndpoint(const std::string& host, const std::string& url) {
	return host + url;
}

static bool isIpv4ClientExternal(const IpAddressChecker& ipChecker, const in_addr& clientAddrBinary) {
	return ipChecker.isV4AddressExternal(clientAddrBinary);
}

static bool isIpv6ClientExternal(const IpAddressChecker& ipChecker, const in6_addr& clientAddrBinary) {
	return ipChecker.isV6AddressExternal(clientAddrBinary);
}

static bool isClientExternal(const IpAddressChecker& ipChecker, const std::variant<in_addr, in6_addr>& clientAddrBinary, bool isIpv6) {
	return isIpv6 ? isIpv6ClientExternal(ipChecker, std::get<in6_addr>(clientAddrBinary)) : isIpv4ClientExternal(ipChecker, std::get<in_addr>(clientAddrBinary));
}

static bool enableNetworkCounters;
static void incrementServiceClientsNumber(
		const IpAddressChecker& ipChecker, Service& service, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta, const std::chrono::time_point<std::chrono::steady_clock>& currentTime) {
	bool isExternal{false};
	bool isIpv6{false};
	std::string clientAddr;

	std::variant<in_addr, in6_addr> clientAddrBinary{};
	try {
		if (!request.clientIp.empty()) {
			clientAddr = request.clientIp.front();
			if (std::count(clientAddr.begin(), clientAddr.end(), ':') >= 2) { //Is possibly IPv6?
				isIpv6 = true;
			}
		} else if (discoveryFlagsSessionIsIPv4(meta.flags)) {
			clientAddr = ipv4ToString(meta.sourceIP.data);
		} else if (discoveryFlagsSessionIsIPv6(meta.flags)) {
			clientAddr = ipv6ToString(meta.sourceIP.data);
			isIpv6 = true;
		} else {
			return;
		}

		if (isIpv6) {
			clientAddrBinary = in6_addr{};
			if (inet_pton(AF_INET6, clientAddr.c_str(), &clientAddrBinary) != 1) {
				throw std::runtime_error("Couldn't parse IPv6 client address");
			}
		} else {
			clientAddrBinary = in_addr{};
			if (inet_pton(AF_INET, clientAddr.c_str(), &std::get<in_addr>(clientAddrBinary)) != 1) {
				throw std::runtime_error("Couldn't parse IPv4 client address");
			}
		}
		isExternal = isClientExternal(ipChecker, clientAddrBinary, isIpv6);
	} catch (const std::runtime_error& e) {
		LOG_TRACE("Couldn't determine if the client is external: {} (client address: {})", e.what(), clientAddr);
		return;
	} catch (const std::bad_variant_access& e) {
		LOG_TRACE("Bad variant access: {} (client address: {})", e.what(), clientAddr);
		return;
	}

	if (isExternal) {
		++service.externalClientsNumber;

		if (enableNetworkCounters) {
			try {
				if (isIpv6) {
					std::array<uint8_t, service::ipv6NetworkPrefixBytesLen> networkIPv6{};
					std::memcpy(networkIPv6.data(), std::get<in6_addr>(clientAddrBinary).s6_addr, service::ipv6NetworkPrefixBytesLen);
					service.detectedExternalIPv6Networks[networkIPv6] = currentTime;
				} else {
					uint32_t network24 = (std::get<in_addr>(clientAddrBinary).s_addr & 0xFFFFFF);
					service.detectedExternalIPv4_24Networks[network24] = currentTime;

					uint32_t network16 = (std::get<in_addr>(clientAddrBinary).s_addr & 0xFFFF);
					service.detectedExternalIPv4_16Networks[network16] = currentTime;
				}
			} catch (const std::bad_variant_access& e) {
				LOG_TRACE("Bad variant access during network counters processing: {} (client address: {})", e.what(), clientAddr);
				return;
			}
		}
	} else {
		++service.internalClientsNumber;
	}
}

static Service toService(const IpAddressChecker& ipChecker, const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta, const std::chrono::time_point<std::chrono::steady_clock>& currentTime) {
	Service service;
	service.pid = meta.pid;
	service.endpoint = getEndpoint(request.host, request.url);

	if (const auto ipv6StartPos = request.host.find('['); ipv6StartPos != std::string::npos) {
		if (const auto ipv6EndPos = request.host.find(']', ipv6StartPos + 1); ipv6EndPos != std::string::npos) {
			service.domain = request.host.substr(ipv6StartPos, ipv6EndPos - ipv6StartPos + 1);
		} else {
			LOG_TRACE("Incorrect request host IPv6 address: {}", request.host);
		}
	} else {
		service.domain = request.host.substr(0, request.host.find(':'));
	}

	service.scheme = request.isHttps ? "https" : "http";
	incrementServiceClientsNumber(ipChecker, service, request, meta, currentTime);
	return service;
}

Aggregator::Aggregator(const IpAddressChecker& ipChecker, bool _enableNetworkCounters) : ipChecker{ipChecker} {
	enableNetworkCounters = _enableNetworkCounters;
}

void Aggregator::clear() {
	std::lock_guard<std::mutex> lock(servicesMutex);
	if (enableNetworkCounters) {
		for (auto it = services.begin(); it != services.end();) {
			if (it->second.detectedExternalIPv4_16Networks.empty() &&
				it->second.detectedExternalIPv4_24Networks.empty() &&
				it->second.detectedExternalIPv6Networks.empty()) {
				it = services.erase(it);
			} else {
				it->second.externalClientsNumber = 0;
				it->second.internalClientsNumber = 0;
				++it;
			}
		}
	} else {
		services.clear();
	}
}

void Aggregator::newRequest(const httpparser::HttpRequest& request, const DiscoverySessionMeta& meta) {
	const auto endpoint{getEndpoint(request.host, request.url)};
	ServiceKey key{meta.pid, endpoint};

	std::lock_guard<std::mutex> lock(servicesMutex);
	const auto it{services.find(key)};
	if (it != services.end()) {
		incrementServiceClientsNumber(ipChecker, it->second, request, meta, getCurrentTime());
		return;
	}
	auto newService{toService(ipChecker, request, meta, getCurrentTime())};

	services[key] = std::move(newService);
}

std::vector<std::reference_wrapper<Service>> Aggregator::collectServices() {
	std::lock_guard<std::mutex> lock(servicesMutex);
	std::vector<std::reference_wrapper<Service>> servicesVec;
	servicesVec.reserve(services.size());

	for (auto& pair : services) {
		servicesVec.emplace_back(pair.second);
	}

	return servicesVec;
}
void Aggregator::networkCountersCleaning() {
	const auto retentionTime = std::chrono::hours(1);
	std::lock_guard<std::mutex> lock(servicesMutex);
	for (auto& service : services) {
		auto currentTime = getCurrentTime();
		for (auto detectedExternalIPv416NetworksIt = service.second.detectedExternalIPv4_16Networks.begin(); detectedExternalIPv416NetworksIt != service.second.detectedExternalIPv4_16Networks.end();) {
			if (currentTime - detectedExternalIPv416NetworksIt->second >= retentionTime) {
				detectedExternalIPv416NetworksIt = service.second.detectedExternalIPv4_16Networks.erase(detectedExternalIPv416NetworksIt);
			} else {
				++detectedExternalIPv416NetworksIt;
			}
		}
		for (auto detectedExternalIPv424NetworksIt = service.second.detectedExternalIPv4_24Networks.begin(); detectedExternalIPv424NetworksIt != service.second.detectedExternalIPv4_24Networks.end();) {
			if (currentTime - detectedExternalIPv424NetworksIt->second >= retentionTime) {
				detectedExternalIPv424NetworksIt = service.second.detectedExternalIPv4_24Networks.erase(detectedExternalIPv424NetworksIt);
			} else {
				++detectedExternalIPv424NetworksIt;
			}
		}
		for (auto detectedExternalIPv6NetworksIt = service.second.detectedExternalIPv6Networks.begin(); detectedExternalIPv6NetworksIt != service.second.detectedExternalIPv6Networks.end();) {
			if (currentTime - detectedExternalIPv6NetworksIt->second >= retentionTime) {
				detectedExternalIPv6NetworksIt = service.second.detectedExternalIPv6Networks.erase(detectedExternalIPv6NetworksIt);
			} else {
				++detectedExternalIPv6NetworksIt;
			}
		}
	}
}

std::mutex& Aggregator::getServicesMutex() {
	return servicesMutex;
}

bool Aggregator::getEnableNetworkCounters() const {
	return enableNetworkCounters;
}

std::chrono::time_point<std::chrono::steady_clock> Aggregator::getCurrentTime() const {
	return std::chrono::steady_clock::now();
}

} // namespace service
