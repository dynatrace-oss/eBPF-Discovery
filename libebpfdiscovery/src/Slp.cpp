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

#include "ebpfdiscovery/Slp.h"
#include "logging/Logger.h"

#include <boost/json.hpp>

#include <iostream>

namespace ebpfdiscovery {

// Hardcoded example processes returned until real BPF-based collection is wired in.
static constexpr std::array<SlpProcess, 3> exampleProcesses{{
	{.pid = 1001, .ppid = 1, .startTs = 1000000, .cpuTime = 50},
	{.pid = 1002, .ppid = 1001, .startTs = 1000100, .cpuTime = 10},
	{.pid = 1003, .ppid = 1, .startTs = 1000200, .cpuTime = 200},
}};

void Slp::outputToStdout(const std::vector<SlpProcess>& processes) {
	boost::json::array arr;
	arr.reserve(processes.size());
	for (const auto& proc : processes) {
		arr.push_back(boost::json::value_from(proc));
	}
	const boost::json::object outJson{{"processes", std::move(arr)}};
	std::cout << boost::json::serialize(outJson) << '\n';
}

void Slp::collectAndOutput() {
	LOG_DEBUG("Outputting short-lived process example data.");
	outputToStdout({exampleProcesses.begin(), exampleProcesses.end()});
}

} // namespace ebpfdiscovery