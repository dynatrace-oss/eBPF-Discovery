/*
* Copyright 2026 Dynatrace LLC
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

#include "ebpfdiscovery/SlpBpf.h"

#include <gtest/gtest.h>

#include <boost/json.hpp>
#include <sstream>
#include <string>
#include <vector>

using ebpfdiscovery::SlpBpf;
using ebpfdiscovery::SlpProcess;

class SlpBpfTest : public testing::Test {};

static bool isParsableJson(const std::string& s) {
	boost::system::error_code ec;
	boost::json::parse(s, ec);
	return !ec;
}

// Build the JSON string for a list of processes the same way Slp::outputToStdout does,
// without the trailing newline, so tests can do exact string comparisons.
static std::string processesToJson(const std::vector<SlpProcess>& processes) {
	boost::json::array arr;
	arr.reserve(processes.size());
	for (const auto& proc : processes) {
		arr.push_back(boost::json::value_from(proc));
	}
	const boost::json::object outJson{{"processes", std::move(arr)}};
	return boost::json::serialize(outJson);
}

// ---------------------------------------------------------------------------
// JSON serialisation tests
// ---------------------------------------------------------------------------

TEST_F(SlpBpfTest, singleProcessJsonFormat) {
	const std::vector<SlpProcess> processes{{.pid = 42, .ppid = 1, .startTs = 123456789ULL, .cpuTime = 100ULL}};

	const std::string result{processesToJson(processes)};

	const std::string expected{R"({"processes":[{"pid":42,"ppid":1,"startTs":123456789,"cpuTime":100}]})"};
	EXPECT_TRUE(isParsableJson(result));
	EXPECT_EQ(result, expected);
}

TEST_F(SlpBpfTest, multipleProcessesJsonFormat) {
	const std::vector<SlpProcess> processes{
			{.pid = 1, .ppid = 0, .startTs = 100ULL, .cpuTime = 10ULL},
			{.pid = 2, .ppid = 1, .startTs = 200ULL, .cpuTime = 20ULL},
			{.pid = 3, .ppid = 1, .startTs = 300ULL, .cpuTime = 0ULL},
	};

	const std::string result{processesToJson(processes)};

	const std::string expected{
			R"({"processes":[)"
			R"({"pid":1,"ppid":0,"startTs":100,"cpuTime":10},)"
			R"({"pid":2,"ppid":1,"startTs":200,"cpuTime":20},)"
			R"({"pid":3,"ppid":1,"startTs":300,"cpuTime":0})"
			R"(]})"};
	EXPECT_TRUE(isParsableJson(result));
	EXPECT_EQ(result, expected);
}

TEST_F(SlpBpfTest, emptyProcessListProducesEmptyArray) {
	const std::vector<SlpProcess> processes{};

	const std::string result{processesToJson(processes)};

	EXPECT_TRUE(isParsableJson(result));
	EXPECT_EQ(result, R"({"processes":[]})");
}

// ---------------------------------------------------------------------------
// Stdout output test
// ---------------------------------------------------------------------------

TEST_F(SlpBpfTest, outputToStdoutProducesValidJson) {
	// Redirect stdout, call Slp::outputToStdout, then verify the captured line.
	const std::vector<SlpProcess> processes{{.pid = 10, .ppid = 1, .startTs = 42ULL, .cpuTime = 7ULL}};

	// Capture stdout
	std::streambuf* const origBuf{std::cout.rdbuf()};
	std::ostringstream captured;
	std::cout.rdbuf(captured.rdbuf());

	SlpBpf::outputToStdout(processes);

	std::cout.rdbuf(origBuf);

	const std::string output{captured.str()};
	EXPECT_FALSE(output.empty());
	EXPECT_TRUE(isParsableJson(output));

	boost::system::error_code ec;
	const auto parsed{boost::json::parse(output, ec)};
	ASSERT_FALSE(ec) << ec.message();
	EXPECT_TRUE(parsed.as_object().contains("processes"));
}