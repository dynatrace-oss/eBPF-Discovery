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

#include "ebpfdiscovery/Dvm.h"

#include "logging/Logger.h"

#include <boost/json.hpp>

#include <iostream>
#include <stdexcept>
#include <unistd.h>

namespace ebpfdiscovery {

namespace {

uint64_t nsToTicks(uint64_t ns) {
	static constexpr uint64_t kNanosInSec = 1'000'000'000;
	static const auto clockTicks = sysconf(_SC_CLK_TCK);
	return ns * clockTicks / kNanosInSec;
}

} // namespace

Dvm::Dvm(std::unique_ptr<LibBpfInterface> libBpfInterface) : libBpfCalls(std::move(libBpfInterface)) {
	if (!libBpfCalls) {
		libBpfCalls = std::make_unique<LibBpfInterface>();
	}
}

Dvm::~Dvm() {
	unload();
}

dvm_bpf* Dvm::openBpf(const bpf_object_open_opts& openOpts) {
	return dvm_bpf__open_opts(&openOpts);
}

int Dvm::loadBpf(dvm_bpf* prog) {
	return dvm_bpf__load(prog);
}

void Dvm::destroyBpf(dvm_bpf* prog) {
	dvm_bpf__destroy(prog);
}

void Dvm::outputToStdout(const std::vector<DvmLibraryLoad>& loads) {
	if (loads.empty()) {
		return;
	}
	boost::json::array arr;
	arr.reserve(loads.size());
	for (const auto& load : loads) {
		arr.push_back(boost::json::value_from(load));
	}
	const boost::json::object outJson{{"libraryLoads", std::move(arr)}};
	std::cout << boost::json::serialize(outJson) << std::endl;
}

void Dvm::collectAndOutput() {
	libBpfCalls->pollEvents(dvmEventsBuffer, 0);
	LOG_DEBUG("Outputting DVM library load data. Number of events: {}", libraryLoads.size());
	outputToStdout(libraryLoads);
	libraryLoads.clear();
}

void addDvmLibraryLoad(Dvm& dvm, const DvmEvent& event) {
	DvmLibraryLoad load{
		.pid = static_cast<pid_t>(event.pid),
		.libraryType = event.libraryType,
		.loadTs = nsToTicks(event.loadTimeNs),
	};
	dvm.libraryLoads.emplace_back(load);
}

void Dvm::load(const bpf_object_open_opts& openOpts) {
	LOG_TRACE("Opening DVM BPF object.");
	skel = openBpf(openOpts);
	if (!skel) {
		throw std::runtime_error("Failed to open DVM BPF object.");
	}

	LOG_TRACE("Loading DVM BPF program.");
	if (const auto res{loadBpf(skel)}) {
		throw std::runtime_error("Failed to load DVM BPF object: " + std::to_string(res));
	}

	LOG_TRACE("Attaching DVM vfs_open kprobe hook.");
	auto link = libBpfCalls->attachProgram(skel->progs.dvmVfsOpenHook);
	if (link == nullptr) {
		throw std::runtime_error("Couldn't attach DVM vfs_open BPF program.");
	}

	LOG_TRACE("Attaching DVM sched_process_exit hook.");
	auto exitLink = libBpfCalls->attachProgram(skel->progs.dvmSchedProcessExit);
	if (exitLink == nullptr) {
		throw std::runtime_error("Couldn't attach DVM sched_process_exit BPF program.");
	}


int eventsMapFd = libBpfCalls->getMapFd(skel->maps.dvmEvents);
	if (eventsMapFd == -EINVAL) {
		throw std::runtime_error("Failed to get DVM events ring buffer fd.");
	}

	LOG_TRACE("Creating DVM events ring buffer.");
	dvmEventsBuffer = libBpfCalls->createRingBuffer(eventsMapFd, [](void* ctx, void* data, size_t) {
		auto* dvm = static_cast<Dvm*>(ctx);
		auto* event = static_cast<struct DvmEvent*>(data);
		addDvmLibraryLoad(*dvm, *event);
		return 0;
	}, this, nullptr);
	if (!dvmEventsBuffer) {
		throw std::runtime_error("Failed to create DVM events ring buffer.");
	}
}

void Dvm::unload() {
	if (dvmEventsBuffer) {
		libBpfCalls->freeRingBuffer(dvmEventsBuffer);
		dvmEventsBuffer = nullptr;
	}
	if (skel) {
		destroyBpf(skel);
		skel = nullptr;
	}
}

} // namespace ebpfdiscovery
