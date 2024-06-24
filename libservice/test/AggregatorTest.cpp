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
		<< ")";
}
} // namespace service

class IpAddressCheckerMock : public IpAddressChecker {
public:
	MOCK_METHOD(bool, isV4AddressExternal, (IPv4int), (const));
	MOCK_METHOD(bool, isV6AddressExternal, (const in6_addr&), (const));
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
	Aggregator aggregator{ipCheckerMock};
};

TEST_F(ServiceAggregatorTest, aggregate) {
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


	{
		auto services{aggregator.collectServices()};
		EXPECT_EQ(services.size(), 6);

		Service expectedService1{.pid = 100, .endpoint{"host/url"}, .internalClientsNumber = 0, .externalClientsNumber = 1, .domain = "host", .scheme = "http"};
		Service expectedService2{.pid = 100, .endpoint{"host/url2"}, .internalClientsNumber = 1, .externalClientsNumber = 0, .domain = "host", .scheme = "http"};
		Service expectedService3{.pid = 200, .endpoint{"host/url2"}, .internalClientsNumber = 1, .externalClientsNumber = 2, .domain = "host", .scheme = "http"};
		Service expectedService4{.pid = 400, .endpoint{"google.com/url123"}, .internalClientsNumber = 0, .externalClientsNumber = 1, .domain = "google.com", .scheme = "http"};
		Service expectedService5{.pid = 500, .endpoint{"8.8.8.8/url123"}, .internalClientsNumber = 0, .externalClientsNumber = 1, .domain = "8.8.8.8", .scheme = "http"};
		Service expectedService6{.pid = 600, .endpoint{"dynatrace.com/url123"}, .internalClientsNumber = 0, .externalClientsNumber = 1, .domain = "dynatrace.com", .scheme = "https"};

		std::vector<Service> servicesCopy;
		std::transform(services.begin(), services.end(), std::back_inserter(servicesCopy), [](const auto& ref) { return ref.get(); });

		EXPECT_THAT(servicesCopy, testing::Contains(expectedService1));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService2));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService3));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService4));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService5));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService6));
	}

	aggregator.clear();
	EXPECT_EQ(aggregator.collectServices().size(), 0);
}
