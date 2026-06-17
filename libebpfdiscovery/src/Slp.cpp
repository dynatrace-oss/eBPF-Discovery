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

Slp::Slp(std::unique_ptr<LibBpfInterface> libBpfInterface) : libBpfCalls(std::move(libBpfInterface)) {
	if (!libBpfCalls) {
		libBpfCalls = std::make_unique<LibBpfInterface>();
	}
}
Slp::~Slp() {
	unload();
}

slp_bpf* Slp::openBpf(const bpf_object_open_opts& openOpts) {
	return slp_bpf__open_opts(&openOpts);
}

int Slp::loadBpf(slp_bpf* prog) {
	return slp_bpf__load(prog);
}

void Slp::destroyBpf(slp_bpf* prog) {
	slp_bpf__destroy(prog);
}

void Slp::outputToStdout(const std::vector<SlpProcess>& processes) {
	if ( processes.empty() ) {
		return;
	}
	boost::json::array arr;
	arr.reserve(processes.size());
	for (const auto& proc : processes) {
		arr.push_back(boost::json::value_from(proc));
	}
	const boost::json::object outJson{{"processes", std::move(arr)}};
	std::cout << boost::json::serialize(outJson) << '\n';
}

void Slp::collectAndOutput() {
	LOG_DEBUG("Outputting short-lived process data. Number of processes {}", processes.size());
	libBpfCalls->pollEvents(slpEventsBuffer, 0);
	outputToStdout(processes);
	processes.clear();
}

void addSlpProcess(Slp& slp, const SlpEvent& event) {
	SlpProcess process{
		.pid = static_cast<pid_t>(event.pid),
		.ppid = static_cast<pid_t>(event.parentPid),
		.cpuTime = event.cpuTimeNs,
		.startTs = event.startTimeNs,
	};
	slp.processes.emplace_back(process);
}

void Slp::load(const bpf_object_open_opts& openOpts) {
	LOG_TRACE("Opening Slp BPF object.");
	skel = openBpf(openOpts);
	if (!skel) {
		throw std::runtime_error("Failed to open BPF object.");
	}

	LOG_TRACE("Loading Slp BPF program.");
	if (const auto res{loadBpf(skel)}) {
		throw std::runtime_error("Failed to load BPF object: " + std::to_string(res));
	}

	LOG_TRACE("Attaching Slp BPF Fork program.");
	auto link = libBpfCalls->attachProgram(skel->progs.processForkHook);
	if (link == nullptr) {
		throw std::runtime_error("couldn't attach fork bpf program");
	}

	LOG_TRACE("Attaching Slp BPF Exit program.");
	link = libBpfCalls->attachProgram(skel->progs.processExitHook);
	if (link == nullptr) {
		throw std::runtime_error("couldn't attach exit bpf program");
	}

	int eventsMapFd = libBpfCalls->getMapFd(skel->maps.slpEvents);
	if (eventsMapFd == -EINVAL) {
		throw std::runtime_error("Failed to load BPF events buffer");
	}

	LOG_TRACE("Creating Slp events buffer program.");
	slpEventsBuffer = libBpfCalls->createRingBuffer(eventsMapFd, [](void* ctx, void* data, size_t) {
		auto slp = static_cast<Slp*>(ctx);
		auto event = static_cast<struct SlpEvent*>(data);
		addSlpProcess(*slp, *event);
		return 0;
	}, this, nullptr);
	if (!slpEventsBuffer) {
		throw std::runtime_error("Failed to create SLP events ring buffer");
	}
}

void Slp::unload() {
	if (slpEventsBuffer) {
		libBpfCalls->freeRingBuffer(slpEventsBuffer);
		slpEventsBuffer = nullptr;
	}
	if (skel) {
		destroyBpf(skel);
		skel = nullptr;
	}
}

} // namespace ebpfdiscovery