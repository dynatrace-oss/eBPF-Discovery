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

#include <bpf/libbpf.h>

#include <cstdint>
#include <sys/types.h>
#include <vector>

#include "ebpfdiscoveryshared/DvmTypes.h"

namespace ebpfdiscovery {

/**
 * Userspace representation of a single managed-runtime library load event.
 *
 * Output JSON schema (one element of the "libraryLoads" array):
 *
 *   {
 *     "pid":         <number>   // PID of the loading process
 *     "libraryType": <number>   // managed-runtime kind (DvmEvent::libraryType)
 *     "loadTs":      <number>   // library load time in clock ticks
 *   }
 *
 * Full envelope:
 *   {"libraryLoads":[{"pid":..,"libraryType":..,"loadTs":..}, ...]}
 *
 * loadTs uses the same clock-tick unit as SlpProcess::startTs (nsToTicks()).
 */
struct DvmLibraryLoad {
	pid_t pid{};
	uint32_t libraryType{};
	uint64_t loadTs{}; /* clock ticks (via nsToTicks) */
};

// cppcheck-suppress unknownMacro
BOOST_DESCRIBE_STRUCT(DvmLibraryLoad, (), (pid, libraryType, loadTs))

/**
 * Delayed VM-detection (DVM) component.
 *
 * Userspace counterpart to the (forthcoming) dvm BPF skeleton.  When the BPF
 * program is wired in, this class will collect managed-runtime library load
 * events and emit them periodically to stdout in the agreed JSON format:
 *
 *   {"libraryLoads":[{"pid":<pid>,"libraryType":<type>,"loadTs":<ts>}, ...]}
 *
 * For this story the BPF skeleton is not yet available; load() and unload()
 * are no-ops, and collectAndOutput() emits nothing.
 *
 * Intended usage (mirrors Slp):
 * @code
 *   ebpfdiscovery::Dvm dvm;
 *   dvm.load(openOpts);
 *   auto future = std::async(std::launch::async, periodicTask, interval,
 *                            [&dvm]{ dvm.collectAndOutput(); });
 * @endcode
 */
class Dvm {
public:
	Dvm() = default;
	virtual ~Dvm();
	Dvm(const Dvm&) = delete;
	Dvm& operator=(const Dvm&) = delete;
	Dvm(Dvm&&) = default;
	Dvm& operator=(Dvm&&) = default;

	/**
	 * Output collected library-load events to stdout as JSON.
	 * No-op until the BPF skeleton is wired in.
	 */
	void collectAndOutput();

	/**
	 * Serialize a list of DvmLibraryLoad entries to stdout as:
	 *   {"libraryLoads":[{"pid":..,"libraryType":..,"loadTs":..}, ...]}
	 * Exposed for unit testing.
	 */
	static void outputToStdout(const std::vector<DvmLibraryLoad>& loads);

	/** No-op until the BPF skeleton is available. */
	void load(const bpf_object_open_opts& openOpts);

	/** No-op until the BPF skeleton is available. */
	void unload();

private:
	std::vector<DvmLibraryLoad> libraryLoads{};
};

} // namespace ebpfdiscovery
