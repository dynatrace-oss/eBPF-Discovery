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
#include <memory>
#include <sys/types.h>
#include <vector>

#include "dvm.skel.h"

#include "ebpfdiscovery/LibBpfInterface.h"
#include "ebpfdiscoveryshared/DvmTypes.h"

namespace ebpfdiscovery {

/**
 * Userspace representation of a single managed-runtime library load event.
 *
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
 * Userspace counterpart to the dvm BPF skeleton (dvm.bpf.c).  Collects
 * managed-runtime library load events via an lsm/mmap_file hook and emits
 * them periodically to stdout in the agreed JSON format:
 *
 *   {"libraryLoads":[{"pid":<pid>,"libraryType":<type>,"loadTs":<ts>}, ...]}
 *
 */
class Dvm {
public:
	explicit Dvm(std::unique_ptr<LibBpfInterface> libBpfInterface = nullptr);
	virtual ~Dvm();
	Dvm(const Dvm&) = delete;
	Dvm& operator=(const Dvm&) = delete;
	Dvm(Dvm&&) = default;
	Dvm& operator=(Dvm&&) = default;

	void collectAndOutput();

	/**
	 * Serialize a list of DvmLibraryLoad entries to stdout as:
	 *   {"libraryLoads":[{"pid":..,"libraryType":..,"loadTs":..}, ...]}
	 * Exposed for unit testing.
	 */
	static void outputToStdout(const std::vector<DvmLibraryLoad>& loads);

	void load(const bpf_object_open_opts& openOpts);
	void unload();

	friend void addDvmLibraryLoad(Dvm& dvm, const DvmEvent& event);

protected:
	virtual dvm_bpf* openBpf(const bpf_object_open_opts& openOpts);
	virtual int loadBpf(dvm_bpf* prog);
	virtual void destroyBpf(dvm_bpf* prog);

private:
	std::unique_ptr<LibBpfInterface> libBpfCalls;
	std::vector<DvmLibraryLoad> libraryLoads{};

	dvm_bpf* skel{nullptr};
	ring_buffer* dvmEventsBuffer{nullptr};
};

} // namespace ebpfdiscovery
