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

#include "service/IpAddressNetlinkChecker.h"

#include <algorithm>
#include <gmock/gmock.h>

using namespace service;

namespace service {
void PrintTo(const Service& service, std::ostream* os) {
	*os << "(" << service.pid << ", " << service.endpoint << ", " << service.internalClientsNumber << ", " << service.externalClientsNumber
		<< ", " << service.detectedExternalIPv4_16Networks.size() << ", " << service.detectedExternalIPv4_24Networks.size() << ", " << service.detectedExternalIPv6Networks.size()
		<< ")";
}
} // namespace service

class IpAddressCheckerMock : public IpAddressChecker {
public:
	MOCK_METHOD(bool, isV4AddressExternal, (IPv4int), (const));
	MOCK_METHOD(bool, isV6AddressExternal, (const in6_addr&), (const));
};

class AggregatorMock : public Aggregator {
public:
	AggregatorMock(const IpAddressCheckerMock& ipCheckerMock, const bool enableNetworkCounters) : Aggregator(ipCheckerMock, enableNetworkCounters) {};

	MOCK_METHOD(std::chrono::time_point<std::chrono::steady_clock>, getCurrentTime, (), (const));
};

struct ServiceAggregatorTest : public testing::Test {
	std::pair<httpparser::HttpRequest, DiscoverySessionMeta> makeRequest(
			int pid, std::string host, std::string url, std::optional<__u8> flags = std::nullopt) {
		httpparser::HttpRequest request;
		request.host = host;
		request.url = url;
		if (flags.has_value()) {
			request.isHttps = flags.value() & DISCOVERY_FLAG_SESSION_SSL_HTTP;
		}
		DiscoverySessionMeta meta{};
		if (flags) {
			meta.flags |= *flags;
		}
		meta.pid = pid;
		return {request, meta};
	}

	const NetlinkCalls netlink;
	IpAddressCheckerMock ipCheckerMock;
};

TEST_F(ServiceAggregatorTest, aggregate) {
	Aggregator aggregator{ipCheckerMock, false};
	EXPECT_EQ(aggregator.collectServices().size(), 0);
	// Service 1
	{
		const auto [request, meta]{makeRequest(100, "host", "/url", DISCOVERY_FLAG_SESSION_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(100, "host", "/url")};
		aggregator.newRequest(request, meta);
	}
	// Service 2
	{
		auto [request, meta]{makeRequest(100, "host", "/url2", DISCOVERY_FLAG_SESSION_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(false));
		aggregator.newRequest(request, meta);
	}
	// Service 3
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_FLAG_SESSION_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_FLAG_SESSION_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(false));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_FLAG_SESSION_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	// Service 4
	{
		const auto [request, meta]{makeRequest(400, "google.com", "/url123", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	// Service 5
	{
		const auto [request, meta]{makeRequest(500, "8.8.8.8", "/url123", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	// Service 6
	{
		const auto [request, meta]{makeRequest(600, "dynatrace.com", "/url123", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_SSL_HTTP)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	// Service 7
	{
		const auto [request, meta]{makeRequest(700, "[::1]", "/url123", DISCOVERY_FLAG_SESSION_IPV6 | DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP)};
		EXPECT_CALL(ipCheckerMock, isV6AddressExternal).WillOnce(testing::Return(false));
		aggregator.newRequest(request, meta);
	}
	// Service 8
	{
		const auto [request, meta]{makeRequest(800, "[2001:0db8:85a3:0001:0000:0000:0000:0000]", "/url123", DISCOVERY_FLAG_SESSION_IPV6 | DISCOVERY_FLAG_SESSION_SSL_HTTP)};
		EXPECT_CALL(ipCheckerMock, isV6AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	// Service 9
	{
		const auto [request, meta]{makeRequest(900, "[2001:0db8:85a3:0001::]", "/url123", DISCOVERY_FLAG_SESSION_IPV6 | DISCOVERY_FLAG_SESSION_SSL_HTTP)};
		EXPECT_CALL(ipCheckerMock, isV6AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}


	{
		auto services{aggregator.collectServices()};
		EXPECT_EQ(services.size(), 9);

		Service expectedService1{.pid = 100, .endpoint{"host/url"}, .domain = "host", .scheme = "http", .internalClientsNumber = 0, .externalClientsNumber = 1};
		Service expectedService2{.pid = 100, .endpoint{"host/url2"}, .domain = "host", .scheme = "http", .internalClientsNumber = 1, .externalClientsNumber = 0};
		Service expectedService3{.pid = 200, .endpoint{"host/url2"}, .domain = "host", .scheme = "http", .internalClientsNumber = 1, .externalClientsNumber = 2};
		Service expectedService4{.pid = 400, .endpoint{"google.com/url123"}, .domain = "google.com", .scheme = "http", .internalClientsNumber = 0, .externalClientsNumber = 1};
		Service expectedService5{.pid = 500, .endpoint{"8.8.8.8/url123"}, .domain = "8.8.8.8", .scheme = "http", .internalClientsNumber = 0, .externalClientsNumber = 1};
		Service expectedService6{.pid = 600, .endpoint{"dynatrace.com/url123"}, .domain = "dynatrace.com", .scheme = "https", .internalClientsNumber = 0, .externalClientsNumber = 1};
		Service expectedService7{.pid = 700, .endpoint{"[::1]/url123"}, .domain = "[::1]", .scheme = "http", .internalClientsNumber = 1, .externalClientsNumber = 0};
		Service expectedService8{.pid = 800, .endpoint{"[2001:0db8:85a3:0001:0000:0000:0000:0000]/url123"}, .domain = "[2001:0db8:85a3:0001:0000:0000:0000:0000]", .scheme = "https", .internalClientsNumber = 0, .externalClientsNumber = 1};
		Service expectedService9{.pid = 900, .endpoint{"[2001:0db8:85a3:0001::]/url123"}, .domain = "[2001:0db8:85a3:0001::]", .scheme = "https", .internalClientsNumber = 0, .externalClientsNumber = 1};

		std::vector<Service> servicesCopy;
		std::transform(services.begin(), services.end(), std::back_inserter(servicesCopy), [](const auto& ref) { return ref.get(); });

		EXPECT_THAT(servicesCopy, testing::Contains(expectedService1));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService2));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService3));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService4));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService5));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService6));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService7));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService8));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService9));
	}

	aggregator.clear();
	EXPECT_EQ(aggregator.collectServices().size(), 0);
}

TEST_F(ServiceAggregatorTest, aggregateNetworkCounters) {
	AggregatorMock aggregator{ipCheckerMock, true};

	EXPECT_EQ(aggregator.collectServices().size(), 0);
	// Service 1
	{
		EXPECT_CALL(aggregator, getCurrentTime).Times(5).WillRepeatedly(testing::Return(std::chrono::time_point<std::chrono::steady_clock>{}));
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).Times(3).WillRepeatedly(testing::Return(true));
		EXPECT_CALL(ipCheckerMock, isV6AddressExternal).Times(2).WillRepeatedly(testing::Return(true));

		std::pair<httpparser::HttpRequest, DiscoverySessionMeta> request{};

		request = makeRequest(100, "host", "/url", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP);
		request.first.clientIp = {"172.143.4.5"};
		aggregator.newRequest(request.first, request.second);

		request = makeRequest(100, "host", "/url", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP);
		request.first.clientIp = {"172.143.6.89"};
		aggregator.newRequest(request.first, request.second);

		request = makeRequest(100, "host", "/url", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP);
		request.first.clientIp = {"172.199.45.55"};
		aggregator.newRequest(request.first, request.second);

		request = makeRequest(100, "host", "/url", DISCOVERY_FLAG_SESSION_IPV6 | DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP);
		request.first.clientIp = {"1234:2345:3456:4567:5678:6789:7890:8901"};
		aggregator.newRequest(request.first, request.second);

		request = makeRequest(100, "host", "/url", DISCOVERY_FLAG_SESSION_IPV6 | DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP);
		request.first.clientIp = {"2001:4860:4860:0000:0000:0000:0000:8888"};
		aggregator.newRequest(request.first, request.second);
	}
	// Service 2
	{
		EXPECT_CALL(aggregator, getCurrentTime).Times(5).WillRepeatedly(testing::Return(std::chrono::time_point<std::chrono::steady_clock>{}));
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).Times(3).WillRepeatedly(testing::Return(true));
		EXPECT_CALL(ipCheckerMock, isV6AddressExternal).Times(2).WillRepeatedly(testing::Return(true));

		std::pair<httpparser::HttpRequest, DiscoverySessionMeta> request{};

		request = makeRequest(200, "host", "/url", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_SSL_HTTP);
		request.first.clientIp = {"172.143.4.5"};
		aggregator.newRequest(request.first, request.second);

		request = makeRequest(200, "host", "/url", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_SSL_HTTP);
		request.first.clientIp = {"172.143.6.89"};
		aggregator.newRequest(request.first, request.second);

		request = makeRequest(200, "host", "/url", DISCOVERY_FLAG_SESSION_IPV4 | DISCOVERY_FLAG_SESSION_SSL_HTTP);
		request.first.clientIp = {"172.199.45.55"};
		aggregator.newRequest(request.first, request.second);

		request = makeRequest(200, "host", "/url", DISCOVERY_FLAG_SESSION_IPV6 | DISCOVERY_FLAG_SESSION_SSL_HTTP);
		request.first.clientIp = {"1234:2345:3456:4567:5678:6789:7890:8901"};
		aggregator.newRequest(request.first, request.second);

		request = makeRequest(200, "host", "/url", DISCOVERY_FLAG_SESSION_IPV6 | DISCOVERY_FLAG_SESSION_SSL_HTTP);
		request.first.clientIp = {"2001:4860:4860:0000:0000:0000:0000:8888"};
		aggregator.newRequest(request.first, request.second);
	}

	const std::unordered_map<uint32_t, std::chrono::time_point<std::chrono::steady_clock>> detectedExternalIPv416Networks = {
			{0x8FAC, std::chrono::time_point<std::chrono::steady_clock>{}},
			{0xC7AC, std::chrono::time_point<std::chrono::steady_clock>{}}
	};
	const std::unordered_map<uint32_t, std::chrono::time_point<std::chrono::steady_clock>> detectedExternalIPv424Networks = {
			{0x048FAC, std::chrono::time_point<std::chrono::steady_clock>{}},
			{0x068FAC, std::chrono::time_point<std::chrono::steady_clock>{}},
			{0x2DC7AC, std::chrono::time_point<std::chrono::steady_clock>{}}
	};
	const std::unordered_map<std::array<uint8_t, service::ipv6NetworkPrefixBytesLen>, std::chrono::time_point<std::chrono::steady_clock>, service::ArrayHasher> detectedExternalIPv6Networks = {
			{{0x20, 0x01, 0x48, 0x60, 0x48, 0x60}, std::chrono::time_point<std::chrono::steady_clock>{}},
			{{0x12, 0x34, 0x23, 0x45, 0x34, 0x56}, std::chrono::time_point<std::chrono::steady_clock>{}}
	};

	{
		auto services{aggregator.collectServices()};
		EXPECT_EQ(services.size(), 2);

		Service expectedService{.pid = 100, .endpoint{"host/url"}, .domain = "host", .scheme = "http", .internalClientsNumber = 0, .externalClientsNumber = 5, .detectedExternalIPv4_16Networks = detectedExternalIPv416Networks, .detectedExternalIPv4_24Networks = detectedExternalIPv424Networks, .detectedExternalIPv6Networks = detectedExternalIPv6Networks};
		Service expectedService2{.pid = 200, .endpoint{"host/url"}, .domain = "host", .scheme = "https", .internalClientsNumber = 0, .externalClientsNumber = 5, .detectedExternalIPv4_16Networks = detectedExternalIPv416Networks, .detectedExternalIPv4_24Networks = detectedExternalIPv424Networks, .detectedExternalIPv6Networks = detectedExternalIPv6Networks};

		std::vector<Service> servicesCopy;
		std::transform(services.begin(), services.end(), std::back_inserter(servicesCopy), [](const auto& ref) { return ref.get(); });

		EXPECT_THAT(servicesCopy, testing::Contains(expectedService));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService2));
	}

	{
		EXPECT_CALL(aggregator, getCurrentTime).Times(2).WillRepeatedly(testing::Return(std::chrono::time_point<std::chrono::steady_clock>{} + std::chrono::minutes(59)));
		aggregator.networkCountersCleaning();
		aggregator.clear();

		const auto collectedServices = aggregator.collectServices();
		EXPECT_EQ(collectedServices.size(), 2);

		for (const auto& service : collectedServices) {
			EXPECT_EQ(service.get().externalClientsNumber, 0);
			EXPECT_EQ(service.get().detectedExternalIPv4_16Networks.size(), 2);
			EXPECT_EQ(service.get().detectedExternalIPv4_24Networks.size(), 3);
			EXPECT_EQ(service.get().detectedExternalIPv6Networks.size(), 2);
		}
	}

	{
		EXPECT_CALL(aggregator, getCurrentTime).Times(2).WillRepeatedly(testing::Return(std::chrono::time_point<std::chrono::steady_clock>{} + std::chrono::minutes(60)));
		aggregator.networkCountersCleaning();
		aggregator.clear();
		EXPECT_EQ(aggregator.collectServices().size(), 0);
	}
}
