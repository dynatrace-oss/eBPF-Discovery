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
#include <memory>

#include <bpf/libbpf.h>

#include "slp.skel.h"

#include "ebpfdiscovery/LibBpfInterface.h"
#include "ebpfdiscoveryshared/SlpTypes.h"

namespace ebpfdiscovery {
/**
 * Snapshot of a single process captured by the short-lived-process (SLP) pipeline.
 *
 * All time values use the kernel's clock-tick unit (as reported in /proc/<pid>/stat)
 * BPF-sourced nanosecond timestamps from SLP BPF
 */
struct SlpProcess {
	pid_t pid{};
	pid_t ppid{};
	uint64_t startTs{};
	uint64_t cpuTime{};
};

// cppcheck-suppress unknownMacro
BOOST_DESCRIBE_STRUCT(SlpProcess, (), (pid, ppid, startTs, cpuTime))

/**
 * Short-lived process (SLP) detection component.
 *
 * Slp is the userspace counterpart to SlpBpf skeleton (analogous to
 * DiscoveryBpf / Discovery for service discovery).  It is responsible for
 * collecting process lifecycle data and emitting it periodically to stdout in
 * the agreed JSON format:
 *
 *   {"processes":[{"pid":<pid>,"ppid":<ppid>,"startTs":<ts>,"cpuTime":<cpuTime>}, ...]}
 *
 * Collection via BPF tracepoints
 *
 * Intended usage in main():
 * @code
 *   ebpfdiscovery::Slp slp;
 *   auto future = std::async(std::launch::async, periodicTask, interval,
 *                            [&slp]{ slp.collectAndOutput(); });
 * @endcode
 */
class Slp {
public:
	explicit Slp(std::unique_ptr<LibBpfInterface> libBpfInterface = nullptr);
	virtual ~Slp();
	Slp(const Slp&) = delete;
	Slp& operator=(const Slp&) = delete;
	Slp(Slp&&) = default;
	Slp& operator=(Slp&&) = default;

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

	void load(const bpf_object_open_opts& openOpts);
	void unload();

	friend void addSlpProcess(Slp& slp, const SlpEvent& process);
protected:
	virtual slp_bpf* openBpf(const bpf_object_open_opts& openOpts);
	virtual int loadBpf(slp_bpf* prog);
	virtual void destroyBpf(slp_bpf* prog);
private:
	std::unique_ptr<LibBpfInterface> libBpfCalls;
	std::vector<SlpProcess> processes{};

	slp_bpf* skel{nullptr};
	ring_buffer* slpEventsBuffer{nullptr};
};

} // namespace ebpfdiscovery