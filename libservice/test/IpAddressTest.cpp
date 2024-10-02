/*
 * Copyright 2024 Dynatrace LLC
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

#include "service/IpAddress.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>

#include <cstddef>
#include <string>

using namespace service;

TEST(IpAddressTest, testIpv4ToString) {
	uint8_t ipv4[4]{192, 168, 0, 1};
	std::string expect{"192.168.0.1"};
	std::string result{ipv4ToString(ipv4)};
	EXPECT_EQ(result, expect);
}

TEST(IpAddressTest, testInetIpv4ToString) {
	std::string ipString{"192.168.0.1"};
	in_addr_t inAddr{inet_addr(ipString.c_str())};
	std::string result{ipv4ToString(reinterpret_cast<uint8_t*>(&inAddr))};
	EXPECT_EQ(result, ipString);
}

TEST(IpAddressTest, TestIpv6ToString) {
	uint8_t ipv6[16]{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x83, 0x01, 0x23, 0x45, 0x67, 0x89};
	std::string expect{"2001:db8:85a3:8d3:1319:8301:2345:6789"};
	std::string result{ipv6ToString(ipv6)};
	EXPECT_EQ(result, expect);
}

TEST(IpAddressTest, testInetIpv6ToString) {
	std::string ipString{"2001:db8:85a3:8d3:1319:8301:2345:6789"};
	struct in6_addr in6Addr;
	inet_pton(AF_INET6, ipString.c_str(), &in6Addr);
	std::string result{ipv6ToString(reinterpret_cast<uint8_t*>(&in6Addr))};
	EXPECT_EQ(result, ipString);
}

TEST(IpAddressTest, testZeroInetIpv6ToString) {
	std::string ipString{"::"};
	struct in6_addr in6Addr;
	inet_pton(AF_INET6, ipString.c_str(), &in6Addr);
	std::string result{ipv6ToString(reinterpret_cast<uint8_t*>(&in6Addr))};
	EXPECT_EQ(result, ipString);
}
