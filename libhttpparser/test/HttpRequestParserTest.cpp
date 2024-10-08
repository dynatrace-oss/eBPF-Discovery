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

#include "httpparser/HttpRequestParser.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <numeric>

using httpparser::HttpRequestParser;

std::vector<std::string> chunkString(const std::string_view str, int chunkSize) {
	std::vector<std::string> chunks;

	for (size_t startPos = 0; startPos < str.length(); startPos += chunkSize) {
		chunks.push_back(std::string(str.substr(startPos, chunkSize)));
	}

	return chunks;
}

struct HttpRequestTestData {
	std::vector<std::string> requestChunks;
	std::string method;
	std::string url;
	std::string protocol;
	std::string host;
	std::vector<std::string> xForwardedFor;
	bool isHttps;
	bool expectFinished;
	size_t expectTotalBytesParsed;

	HttpRequestTestData(
			std::vector<std::string> requestChunks_ = {},
			std::string method = "",
			std::string url = "",
			std::string protocol = "",
			std::string host = "",
			std::vector<std::string> xForwardedFor = {},
			bool isHttps = false,
			bool expectFinished = true,
			std::optional<size_t> expectTotalBytesParsed_ = std::nullopt)
			: requestChunks(std::move(requestChunks_)),
			  method(std::move(method)),
			  url(std::move(url)),
			  protocol(std::move(protocol)),
			  host(std::move(host)),
			  xForwardedFor(std::move(xForwardedFor)),
			  isHttps(isHttps),
			  expectFinished(expectFinished),
			  expectTotalBytesParsed(expectTotalBytesParsed_.value_or(std::accumulate(
					  requestChunks.begin(), requestChunks.end(), 0, [](int sum, const std::string& str) { return sum + str.length(); }))) {
	}
};
using namespace ::testing;

class HttpRequestParserTest : public Test, public httpparser::HttpRequestParser {
public:
};

TEST_F(HttpRequestParserTest, testParseXForwardedFor) {
	std::string dataToTest = "fe80:0000:0000:0000:0000:0000:0000:0005";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 1);
	EXPECT_EQ("fe80:0000:0000:0000:0000:0000:0000:0005", result.clientIp[0]);

	result.clientIp.clear();

	dataToTest = "203.0.113.195, 70.41.3.18, 150.172.238.178";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 3);
	EXPECT_EQ("203.0.113.195", result.clientIp[0]);
	EXPECT_EQ("70.41.3.18", result.clientIp[1]);
	EXPECT_EQ("150.172.238.178", result.clientIp[2]);

	result.clientIp.clear();

	dataToTest = "203.0.113.195";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 1);
	EXPECT_EQ("203.0.113.195", result.clientIp[0]);

	result.clientIp.clear();

	dataToTest = "2001:db8:85a3:8d3:1319:8a2e:370:7348";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 1);
	EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", result.clientIp[0]);

	result.clientIp.clear();

	dataToTest = "203.0.113.195:41237, 198.51.100.100:38523";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 2);
	EXPECT_EQ("203.0.113.195", result.clientIp[0]);
	EXPECT_EQ("198.51.100.100", result.clientIp[1]);

	result.clientIp.clear();

	dataToTest = "[2001:db8::1a2b:3c4d]:41237, 198.51.100.100:26321";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 2);
	EXPECT_EQ("2001:db8::1a2b:3c4d", result.clientIp[0]);
	EXPECT_EQ("198.51.100.100", result.clientIp[1]);

	result.clientIp.clear();

	dataToTest = "[2001:db8::aa:bb]";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 1);
	EXPECT_EQ("2001:db8::aa:bb", result.clientIp[0]);

	result.clientIp.clear();

	dataToTest = "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 2);
	EXPECT_EQ("203.0.113.195", result.clientIp[0]);
	EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", result.clientIp[1]);

	result.clientIp.clear();

	dataToTest = "203.0.113.195,2001:db8:85a3:8d3:1319:8a2e:370:7348,198.51.100.178";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 3);
	EXPECT_EQ("203.0.113.195", result.clientIp[0]);
	EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", result.clientIp[1]);
	EXPECT_EQ("198.51.100.178", result.clientIp[2]);

	result.clientIp.clear();

	dataToTest = "[2001:db8::1]:30943";
	parseClientIPValue(dataToTest);
	EXPECT_EQ(result.clientIp.size(), 1);
	EXPECT_EQ("2001:db8::1", result.clientIp[0]);
}

class HttpRequestDataParsingTest : public TestWithParam<HttpRequestTestData> {};

TEST_P(HttpRequestDataParsingTest, TestValidRequest) {
	const auto& testData{GetParam()};
	HttpRequestParser parser;
	size_t totalBytesParsed{0};
	for (const auto& chunk : testData.requestChunks) {
		totalBytesParsed += parser.parse(chunk, testData.isHttps ? DISCOVERY_FLAG_SESSION_SSL_HTTP : DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP);
	}

	EXPECT_EQ(parser.isFinished(), testData.expectFinished);
	EXPECT_FALSE(parser.isInvalidState());
	EXPECT_EQ(totalBytesParsed, testData.expectTotalBytesParsed);
	EXPECT_EQ(parser.result.method, testData.method);
	EXPECT_EQ(parser.result.url, testData.url);
	EXPECT_EQ(parser.result.protocol, testData.protocol);
	EXPECT_EQ(parser.result.host, testData.host);
	EXPECT_EQ(parser.result.clientIp, testData.xForwardedFor);
	EXPECT_EQ(parser.result.isHttps, testData.isHttps);
}

struct HttpRequestTestInvalidData {
	std::vector<std::string> requestChunks;
	size_t expectTotalBytesParsed;
};

class HttpRequestParserTestInvalid : public ::testing::TestWithParam<HttpRequestTestInvalidData> {};

TEST_P(HttpRequestParserTestInvalid, testInvalidRequest) {
	const auto& testData{GetParam()};
	HttpRequestParser parser;
	size_t totalBytesParsed{0};
	for (const auto& chunk : testData.requestChunks) {
		totalBytesParsed += parser.parse(chunk, DISCOVERY_FLAG_SESSION_UNENCRYPTED_HTTP);
	}

	EXPECT_TRUE(parser.isFinished());
	EXPECT_TRUE(parser.isInvalidState());
	EXPECT_EQ(totalBytesParsed, testData.expectTotalBytesParsed);
}

INSTANTIATE_TEST_SUITE_P(
		Default,
		HttpRequestDataParsingTest,
		::testing::Values(
				HttpRequestTestData{
						{"GET /example HTTP/1.1\r\nHost: example.com\r\n\r\n"}, "GET", "/example", "HTTP/1.1", "example.com", {}},
				HttpRequestTestData{
						{"GET /example HTTP/1.1\r\nHOST: example.com\r\n\r\n"}, "GET", "/example", "HTTP/1.1", "example.com", {}},
				HttpRequestTestData{
						{"POST /example HTTP/1.1\r\nHost: example.com\r\n\r\n"}, "POST", "/example", "HTTP/1.1", "example.com", {}},
				HttpRequestTestData{
						{"POST /example HTTP/1.1\r\nHOST: example.com\r\n\r\n"}, "POST", "/example", "HTTP/1.1", "example.com", {}},
				HttpRequestTestData{
						{"GET /example HTTP/1.0\r\nHost: example.com\r\n\r\n"}, "GET", "/example", "HTTP/1.0", "example.com", {}},
				HttpRequestTestData{
						{"POST /example HTTP/1.0\r\nHost: example.com\r\n\r\n"}, "POST", "/example", "HTTP/1.0", "example.com", {}},
				HttpRequestTestData{
						{"GET /example HTTP/1.1\r\nHost: example.com\r\n\r"}, "GET", "/example", "HTTP/1.1", "example.com", {}, false, false},
				HttpRequestTestData{
						{"GET /Hello%20World/index.html HTTP/1.1\r\nHost:  example.com\r\nx-forwarded-for:  127.0.0.1\r\n\r\n"},
						"GET",
						"/Hello%20World/index.html",
						"HTTP/1.1",
						"example.com",
						{"127.0.0.1"}},
				HttpRequestTestData{{"GET / HTTP/1.1\r\n\r\n"}, "GET", "/", "HTTP/1.1", "", {}},
				HttpRequestTestData{
						chunkString("GET /example HTTP/1.1\r\nHost: example.com\r\n\r\n", 8),
						"GET",
						"/example",
						"HTTP/1.1",
						"example.com",
						{}},
				HttpRequestTestData{
						chunkString("GET /example HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 0.0.0.0\r\n\r\n", 1),
						"GET",
						"/example",
						"HTTP/1.1",
						"example.com",
						{"0.0.0.0"}},
				HttpRequestTestData{
						{"POST /example/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\nX-Forwarded-For: "
						 "192.168.0.1:8080, 10.0.0.1, [2001:0db8:85a3::8a2e:0370:7334]\r\n\r\n{\"name\":\"example\"}\r\n"},
						"POST",
						"/example/",
						"HTTP/1.1",
						"example.com",
						{"192.168.0.1", "10.0.0.1", "2001:0db8:85a3::8a2e:0370:7334"},
						false,
						true,
						163},
				HttpRequestTestData{
						{"POST /example/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\nX-Forwarded-For: "
						 "192.168.0.1:8080, 10.0.0.1, [2001:0db8:85a3::8a2e:0370:7334]\r\n\r\n{\"name\":\"example\"}\r\n"},
						"POST",
						"/example/",
						"HTTP/1.1",
						"example.com",
						{"192.168.0.1", "10.0.0.1", "2001:0db8:85a3::8a2e:0370:7334"},
						true,
						true,
						163},
				HttpRequestTestData{
						chunkString(
								"GET /example/ HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 10.0.0.1\r\nUser-Agent: "
								"curl/7.81.0\r\nAccept: */*\r\nx-forwarded-for: 127.0.0.1,[2001:0db8:85a3::8a2e:0370:7335]:1234\r\n\r\n",
								2),
						"GET",
						"/example/",
						"HTTP/1.1",
						"example.com",
						{"10.0.0.1", "127.0.0.1", "2001:0db8:85a3::8a2e:0370:7335"},
				},
				HttpRequestTestData{chunkString("GET / HTTP/1.1\r\n", 1), "GET", "/", "HTTP/1.1", "", {}, false, false},
				HttpRequestTestData{{"GET /"}, "GET", "/", "", "", {}, false, false},
				HttpRequestTestData{{"", ""}, "", "", "", "", {}, false, false}));

INSTANTIATE_TEST_SUITE_P(
		Default,
		HttpRequestParserTestInvalid,
		::testing::Values(
				HttpRequestTestInvalidData{{"get /example HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 1},
				HttpRequestTestInvalidData{{"post /example HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 1},
				HttpRequestTestInvalidData{{"POST  HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 6},
				HttpRequestTestInvalidData{{"GET / HTTP/1.1\r\nHost: \r\n\r\n"}, 23},
				HttpRequestTestInvalidData{{"GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 5},
				HttpRequestTestInvalidData{{"GET /  HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 7},
				HttpRequestTestInvalidData{{"GET / HTTP/1.1 \r\nHost: example.com\r\n\r\n"}, 15},
				HttpRequestTestInvalidData{{"GET / HTTP/1.1\nHost: example.con\n\n"}, 15},
				HttpRequestTestInvalidData{{"GET /example", "HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 21},
				HttpRequestTestInvalidData{{"\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 1},
				HttpRequestTestInvalidData{{"\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 1},
				HttpRequestTestInvalidData{{"GET / HTTP/0.0\r\nHost: example.com\r\n\r\n"}, 12},
				HttpRequestTestInvalidData{{"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"}, 5}));

