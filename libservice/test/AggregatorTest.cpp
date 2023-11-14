// SPDX-License-Identifier: Apache-2.0
#include "service/Aggregator.h"

#include "service/IpAddressChecker.h"

#include <algorithm>
#include <gmock/gmock.h>

using namespace service;

namespace service {
void PrintTo(const Service& service, std::ostream* os) {
	*os << "(" << service.pid
		<< ", " << service.endpoint
		<< ", " << service.internalClientsNumber
		<< ", " << service.externalClientsNumber << ")";
}
} // namespace service

class IpAddressCheckerMock : public IpAddressChecker {
public:
	using IpAddressChecker::IpAddressChecker;
	MOCK_METHOD(bool, isAddressExternalLocal, (IPv4int), (override));
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
	IpAddressCheckerMock ipCheckerMock{netlink};
	Aggregator aggregator{ipCheckerMock};
};

TEST_F(ServiceAggregatorTest, aggregate) {
	EXPECT_EQ(aggregator.collectServices().size(), 0);
	// Service 1
	{
		const auto [request, meta]{makeRequest(100, "host", "/url", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isAddressExternalLocal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(100, "host", "/url")};
		aggregator.newRequest(request, meta);
	}
	// Service 2
	{
		auto [request, meta]{makeRequest(100, "host", "/url2", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isAddressExternalLocal).WillOnce(testing::Return(false));
		aggregator.newRequest(request, meta);
	}
	// Service 3
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isAddressExternalLocal).WillOnce(testing::Return(true));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isAddressExternalLocal).WillOnce(testing::Return(false));
		aggregator.newRequest(request, meta);
	}
	{
		auto [request, meta]{makeRequest(200, "host", "/url2", DISCOVERY_SESSION_FLAGS_IPV4)};
		EXPECT_CALL(ipCheckerMock, isAddressExternalLocal).WillOnce(testing::Return(true));
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
