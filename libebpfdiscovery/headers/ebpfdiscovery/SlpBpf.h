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

#pragma once

#include <boost/describe.hpp>

#include <cstdint>
#include <sys/types.h>
#include <vector>

namespace ebpfdiscovery {

struct SlpProcess {
	pid_t pid{};
	pid_t ppid{};
	uint64_t startTs{};
	uint64_t cpuTime{};
};

// cppcheck-suppress unknownMacro
BOOST_DESCRIBE_STRUCT(SlpProcess, (), (pid, ppid, startTs, cpuTime))

class SlpBpf {
public:
	SlpBpf() = default;
	SlpBpf(const SlpBpf&) = delete;
	SlpBpf& operator=(const SlpBpf&) = delete;

	/*
	 * Output collected process data to stdout as JSON.
	 * Intended for use as the body of a periodicTask lambda.
	 */
	void collectAndOutput();

	/*
	 * Serialize a list of SlpProcess entries to stdout as:
	 *   {"processes":[{"pid":..,"ppid":..,"startTs":..,"cpuTime":..}, ...]}
	 * Exposed for unit testing.
	 */
	static void outputToStdout(const std::vector<SlpProcess>& processes);
};

} // namespace ebpfdiscovery