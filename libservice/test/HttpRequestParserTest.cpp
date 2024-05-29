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

#include "httpparser/HttpRequestParser.h"

#include <gtest/gtest.h>

using namespace ::testing;

class HttpRequestParserTest : public Test, public httpparser::HttpRequestParser {
public:
};

TEST_F(HttpRequestParserTest, testParseXForwardedFor) {
	std::string dataToTest = "fe80:0000:0000:0000:0000:0000:0000:0005";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 1);
	EXPECT_EQ("fe80:0000:0000:0000:0000:0000:0000:0005", result.xForwardedFor[0]);

	result.xForwardedFor.clear();

	dataToTest = "203.0.113.195, 70.41.3.18, 150.172.238.178";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 3);
	EXPECT_EQ("203.0.113.195", result.xForwardedFor[0]);
	EXPECT_EQ("70.41.3.18", result.xForwardedFor[1]);
	EXPECT_EQ("150.172.238.178", result.xForwardedFor[2]);

	result.xForwardedFor.clear();

	dataToTest = "203.0.113.195";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 1);
	EXPECT_EQ("203.0.113.195", result.xForwardedFor[0]);

	result.xForwardedFor.clear();

	dataToTest = "2001:db8:85a3:8d3:1319:8a2e:370:7348";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 1);
	EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", result.xForwardedFor[0]);

	result.xForwardedFor.clear();

	dataToTest = "203.0.113.195:41237, 198.51.100.100:38523";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 2);
	EXPECT_EQ("203.0.113.195", result.xForwardedFor[0]);
	EXPECT_EQ("198.51.100.100", result.xForwardedFor[1]);

	result.xForwardedFor.clear();

	dataToTest = "[2001:db8::1a2b:3c4d]:41237, 198.51.100.100:26321";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 2);
	EXPECT_EQ("2001:db8::1a2b:3c4d", result.xForwardedFor[0]);
	EXPECT_EQ("198.51.100.100", result.xForwardedFor[1]);

	result.xForwardedFor.clear();

	dataToTest = "[2001:db8::aa:bb]";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 1);
	EXPECT_EQ("2001:db8::aa:bb", result.xForwardedFor[0]);

	result.xForwardedFor.clear();

	dataToTest = "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 2);
	EXPECT_EQ("203.0.113.195", result.xForwardedFor[0]);
	EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", result.xForwardedFor[1]);

	result.xForwardedFor.clear();

	dataToTest = "203.0.113.195,2001:db8:85a3:8d3:1319:8a2e:370:7348,198.51.100.178";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 3);
	EXPECT_EQ("203.0.113.195", result.xForwardedFor[0]);
	EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", result.xForwardedFor[1]);
	EXPECT_EQ("198.51.100.178", result.xForwardedFor[2]);

	result.xForwardedFor.clear();

	dataToTest = "[2001:db8::1]:30943";
	parseXForwardedFor(dataToTest);
	EXPECT_EQ(result.xForwardedFor.size(), 1);
	EXPECT_EQ("2001:db8::1", result.xForwardedFor[0]);
}