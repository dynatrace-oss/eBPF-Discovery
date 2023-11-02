// SPDX-License-Identifier: Apache-2.0

#include "httpparser/HttpRequestParser.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <numeric>

using httpparser::HttpRequestParser;
using httpparser::XForwardedForValueParser;

std::vector<std::string> chunkString(const std::string_view str, int chunkSize) {
	std::vector<std::string> chunks;

	for (size_t startPos = 0; startPos < str.length(); startPos += chunkSize) {
		chunks.push_back(std::string(str.substr(startPos, chunkSize)));
	}

	return chunks;
}

class XForwardedForValueParserTest : public ::testing::Test {
protected:
	XForwardedForValueParser parser;
};

TEST_F(XForwardedForValueParserTest, testIPv4AddressParsing) {
	std::string input{"192.168.0.1,10.0.0.1,9.9.9.9"};
	parser.parse(input);

	const auto& result{parser.result};
	ASSERT_EQ(result.addresses.size(), 3);
	ASSERT_EQ(result.addresses[0], "192.168.0.1");
	ASSERT_EQ(result.addresses[1], "10.0.0.1");
	ASSERT_EQ(result.addresses[2], "9.9.9.9");
}

TEST_F(XForwardedForValueParserTest, testIPv6AddressParsing) {
	std::string input{"[2001:0db8:85a3::8a2e:0370:7334],[2001:0db8:85a3::8a2e:0370:7335]"};
	parser.parse(input);

	const auto& result{parser.result};
	ASSERT_EQ(result.addresses.size(), 2);
	ASSERT_EQ(result.addresses[0], "[2001:0db8:85a3::8a2e:0370:7334]");
	ASSERT_EQ(result.addresses[1], "[2001:0db8:85a3::8a2e:0370:7335]");
}

TEST_F(XForwardedForValueParserTest, testDomainAddressParsing) {
	std::string input{"example.com:1234,example.org:8080"};
	parser.parse(input);

	const auto& result = parser.result;
	ASSERT_EQ(result.addresses.size(), 2);
	ASSERT_EQ(result.addresses[0], "example.com:1234");
	ASSERT_EQ(result.addresses[1], "example.org:8080");
}

struct HttpRequestTestData {
	std::vector<std::string> requestChunks;
	std::string method;
	std::string url;
	std::string protocol;
	std::string host;
	std::string xForwardedFor;
	bool expectFinished;
	size_t expectTotalBytesParsed;

	HttpRequestTestData(
			std::vector<std::string> requestChunks_ = {},
			std::string method = "",
			std::string url = "",
			std::string protocol = "",
			std::string host = "",
			std::string xForwardedFor = "",
			bool expectFinished = true,
			std::optional<size_t> expectTotalBytesParsed_ = std::nullopt)
			: requestChunks(std::move(requestChunks_)),
			  method(std::move(method)),
			  url(std::move(url)),
			  protocol(std::move(protocol)),
			  host(std::move(host)),
			  xForwardedFor(std::move(xForwardedFor)),
			  expectFinished(expectFinished),
			  expectTotalBytesParsed(expectTotalBytesParsed_.value_or(std::accumulate(
					  requestChunks.begin(), requestChunks.end(), 0, [](int sum, const std::string& str) { return sum + str.length(); }))) {
	}
};

class HttpRequestParserTest : public ::testing::TestWithParam<HttpRequestTestData> {};

TEST_P(HttpRequestParserTest, TestValidRequest) {
	const auto& testData{GetParam()};
	HttpRequestParser parser;
	size_t totalBytesParsed{0};
	for (const auto& chunk : testData.requestChunks) {
		totalBytesParsed += parser.parse(chunk);
	}

	EXPECT_EQ(parser.isFinished(), testData.expectFinished);
	EXPECT_FALSE(parser.isInvalidState());
	EXPECT_EQ(totalBytesParsed, testData.expectTotalBytesParsed);
	EXPECT_EQ(parser.result.method, testData.method);
	EXPECT_EQ(parser.result.url, testData.url);
	EXPECT_EQ(parser.result.protocol, testData.protocol);
	EXPECT_EQ(parser.result.host, testData.host);
	EXPECT_EQ(parser.result.xForwardedFor, testData.xForwardedFor);
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
		totalBytesParsed += parser.parse(chunk);
	}

	EXPECT_TRUE(parser.isFinished());
	EXPECT_TRUE(parser.isInvalidState());
	EXPECT_EQ(totalBytesParsed, testData.expectTotalBytesParsed);
}

INSTANTIATE_TEST_CASE_P(
		Default,
		HttpRequestParserTest,
		::testing::Values(
				HttpRequestTestData{
						{"GET /example HTTP/1.1\r\nHost: example.com\r\n\r\n"}, "GET", "/example", "HTTP/1.1", "example.com", ""},
				HttpRequestTestData{
						{"GET /example HTTP/1.1\r\nHOST: example.com\r\n\r\n"}, "GET", "/example", "HTTP/1.1", "example.com", ""},
				HttpRequestTestData{
						{"POST /example HTTP/1.1\r\nHost: example.com\r\n\r\n"}, "POST", "/example", "HTTP/1.1", "example.com", ""},
				HttpRequestTestData{
						{"POST /example HTTP/1.1\r\nHOST: example.com\r\n\r\n"}, "POST", "/example", "HTTP/1.1", "example.com", ""},
				HttpRequestTestData{
						{"GET /example HTTP/1.0\r\nHost: example.com\r\n\r\n"}, "GET", "/example", "HTTP/1.0", "example.com", ""},
				HttpRequestTestData{
						{"POST /example HTTP/1.0\r\nHost: example.com\r\n\r\n"}, "POST", "/example", "HTTP/1.0", "example.com", ""},
				HttpRequestTestData{
						{"GET /example HTTP/1.1\r\nHost: example.com\r\n\r"}, "GET", "/example", "HTTP/1.1", "example.com", "", false},
				HttpRequestTestData{
						{"GET /Hello%20World/index.html HTTP/1.1\r\nHost:  example.com\r\nx-forwarded-for:  127.0.0.1\r\n\r\n"},
						"GET",
						"/Hello%20World/index.html",
						"HTTP/1.1",
						"example.com",
						"127.0.0.1"},
				HttpRequestTestData{{"GET / HTTP/1.1\r\n\r\n"}, "GET", "/", "HTTP/1.1", "", ""},
				HttpRequestTestData{
						chunkString("GET /example HTTP/1.1\r\nHost: example.com\r\n\r\n", 8),
						"GET",
						"/example",
						"HTTP/1.1",
						"example.com",
						""},
				HttpRequestTestData{
						chunkString("GET /example HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 0.0.0.0\r\n\r\n", 1),
						"GET",
						"/example",
						"HTTP/1.1",
						"example.com",
						"0.0.0.0"},
				HttpRequestTestData{
						{"POST /example/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\nX-Forwarded-For: "
						 "192.168.0.1, 10.0.0.1\r\n\r\n{\"name\":\"example\"}\r\n"},
						"POST",
						"/example/",
						"HTTP/1.1",
						"example.com",
						"192.168.0.1, 10.0.0.1",
						true,
						124},
				HttpRequestTestData{
						chunkString(
								"GET /example/ HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 10.0.0.1\r\nUser-Agent: "
								"curl/7.81.0\r\nAccept: */*\r\nx-forwarded-for: 127.0.0.1\r\n\r\n",
								2),
						"GET",
						"/example/",
						"HTTP/1.1",
						"example.com",
						"10.0.0.1,127.0.0.1",
				},
				HttpRequestTestData{chunkString("GET / HTTP/1.1\r\n", 1), "GET", "/", "HTTP/1.1", "", "", false},
				HttpRequestTestData{{"GET /"}, "GET", "/", "", "", "", false},
				HttpRequestTestData{{"", ""}, "", "", "", "", "", false}));

INSTANTIATE_TEST_CASE_P(
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
