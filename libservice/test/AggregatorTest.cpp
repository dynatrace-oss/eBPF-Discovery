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
		const auto [request, meta]{makeRequest(100, "host", "/url", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(100, "host", "/url")};
		aggregator.newRequest(request, meta);
	}
	// Service 2
	{
		auto [request, meta]{makeRequest(100, "host", "/url2", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(false));
		aggregator.newRequest(request, meta);
	}
	// Service 3
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(false));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isV4AddressExternal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}

	{
		auto services{aggregator.collectServices()};
		EXPECT_EQ(services.size(), 3);

		Service expectedService1{.pid{100}, .endpoint{"host/url"}, .internalClientsNumber{0}, .externalClientsNumber{1}};
		Service expectedService2{.pid{100}, .endpoint{"host/url2"}, .internalClientsNumber{1}, .externalClientsNumber{0}};
		Service expectedService3{.pid{200}, .endpoint{"host/url2"}, .internalClientsNumber{1}, .externalClientsNumber{2}};

		std::vector<Service> servicesCopy;
		std::transform(services.begin(), services.end(), std::back_inserter(servicesCopy), [](const auto& ref) { return ref.get(); });

		EXPECT_THAT(servicesCopy, testing::Contains(expectedService1));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService2));
		EXPECT_THAT(servicesCopy, testing::Contains(expectedService3));
	}

	aggregator.clear();
	EXPECT_EQ(aggregator.collectServices().size(), 0);
}
