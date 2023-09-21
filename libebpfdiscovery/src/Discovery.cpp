// SPDX-License-Identifier: Apache-2.0

#include "ebpfdiscovery/Discovery.h"

#include "StringFunctions.h"
#include "ebpfdiscovery/Session.h"

extern "C" {
#include "bpfload/btf_helpers.h"
}

#include "discovery.skel.h"

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <errno.h>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

namespace ebpfdiscovery {

static void printSession(const Session& session, const DiscoverySessionMeta& meta) {
	const auto& request{session.parser.result};
	std::cout << request.method << " " << request.host << request.url;

	if (const auto& x_forwarded_for{request.x_forwarded_for}; !x_forwarded_for.empty()) {
		std::cout << " X-Forwarded-For: " << '"' << x_forwarded_for << '"';
	} else if (discoverySessionFlagsIsIPv4(meta.flags)) {
		if (auto src_ipv4{ipv4ToString(meta.sourceIPData)}; !src_ipv4.empty())
			std::cout << " src_ipv4: " << '"' << src_ipv4 << '"';
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		if (auto src_ipv6{ipv6ToString(meta.sourceIPData)}; !src_ipv6.empty())
			std::cout << " src_ipv6: " << '"' << src_ipv6 << '"';
	}

	std::cout << '\n';
}

Discovery::Discovery() : Discovery(DiscoveryConfig{}) {
}

Discovery::Discovery(const DiscoveryConfig config) : bpf_open_opts{.sz = sizeof(bpf_open_opts)}, savedSessions(DISCOVERY_MAX_SESSIONS) {
}

Discovery::~Discovery() {
	unload();
}

int Discovery::run() {
	if (bpf_obj == nullptr) {
		return -1;
	}

	running = true;
	while (running) {
		fetchEvents();
		bpfDiscoveryResumeCollecting();
		std::this_thread::sleep_for(config.eventQueuePollInterval);
	}

	return 0;
}

void Discovery::fetchEvents() {
	DiscoveryEvent event;
	while (bpf_map__lookup_and_delete_elem(bpf_obj->maps.eventsToUserspaceQueueMap, NULL, 0, &event, sizeof(event), BPF_ANY) == 0) {
		handleNewEvent(std::move(event));
	}
}

void Discovery::handleNewEvent(DiscoveryEvent event) {
	if (discoveryEventFlagsIsNewData(event.flags)) {
		handleNewDataEvent(event);
	}
	if (discoveryEventFlagsIsNoMoreData(event.flags) || discoveryEventFlagsIsClose(event.flags)) {
		handleCloseEvent(event);
	}
}

void Discovery::handleNewDataEvent(DiscoveryEvent& event) {
	DiscoverySavedBuffer savedBuffer;
	auto lookup_result{bpf_map__lookup_elem(
			bpf_obj->maps.savedBuffersMap, &event.dataKey, sizeof(DiscoverySavedBufferKey), &savedBuffer, sizeof(savedBuffer), BPF_ANY)};
	if (lookup_result != 0) {
		return;
	}

	handleBufferLookupSuccess(savedBuffer, event);
}

void Discovery::handleBufferLookupSuccess(DiscoverySavedBuffer& saved_buffer, DiscoveryEvent& event) {
	std::string_view buffer_view(saved_buffer.data, saved_buffer.length);
	bpf_map__delete_elem(bpf_obj->maps.savedBuffersMap, &event.dataKey, sizeof(DiscoverySavedBufferKey), BPF_ANY);

	auto it{savedSessions.find(event.dataKey)};
	if (it != savedSessions.end()) {
		handleExistingSession(it, buffer_view, event);
		return;
	}

	handleNewSession(buffer_view, event);
}

void Discovery::handleExistingSession(SavedSessionsCacheType::iterator it, std::string_view& buffer_view, DiscoveryEvent& event) {
	savedSessions.update(it, [buffer_view = std::move(buffer_view)](auto& session) { session.parser.parse(std::move(buffer_view)); });
	if (it->second.parser.is_invalid_state()) {
		bpfDiscoveryDeleteSession(event.dataKey);
		savedSessions.erase(it);
		return;
	}

	if (!it->second.parser.is_finished()) {
		// We expect more data buffers to come
		return;
	}

	handleSuccessfulParse(it->second, event.sessionMeta);
	savedSessions.update(it, [](auto& session) { session.reset(); });
}

void Discovery::handleNewSession(std::string_view& buffer_view, DiscoveryEvent& event) {
	Session session;
	session.parser.parse(std::move(buffer_view));
	if (session.parser.is_invalid_state()) {
		bpfDiscoveryDeleteSession(event.dataKey);
		return;
	}

	if (!session.parser.is_finished() && !discoveryEventFlagsIsNoMoreData(event.flags)) {
		saveSession(event.dataKey, std::move(session));
		return;
	}

	if (!session.parser.is_finished()) {
		return;
	}

	handleSuccessfulParse(session, event.sessionMeta);
}

void Discovery::handleCloseEvent(DiscoveryEvent& event) {
	if (auto it{savedSessions.find(event.dataKey)}; it != savedSessions.end()) {
		savedSessions.erase(it);
	}
}

int Discovery::bpfDiscoveryResumeCollecting() {
	static uint32_t zero{0};
	DiscoveryGlobalState discoveryGlobalState{};
	return bpf_map__update_elem(
			bpf_obj->maps.globalStateMap, &zero, sizeof(zero), &discoveryGlobalState, sizeof(discoveryGlobalState), BPF_EXIST);
}

int Discovery::bpfDiscoveryResetConfig() {
	return bpfDiscoveryResumeCollecting();
}

void Discovery::load() {
	if (int res{ensure_core_btf(&bpf_open_opts)}) {
		throw std::runtime_error("Failed to fetch necessary BTF for CO-RE: " + std::string(strerror(-res)));
	}

	bpf_obj = discovery_bpf__open_opts(&bpf_open_opts);
	if (bpf_obj == nullptr) {
		throw std::runtime_error("Failed to open BPF object.");
	}

	if (int res{discovery_bpf__load(bpf_obj)}) {
		throw std::runtime_error("Failed to load BPF object: " + std::to_string(res));
	}

	if (int res{discovery_bpf__attach(bpf_obj)}) {
		throw std::runtime_error("Failed to attach BPF object: " + std::to_string(res));
	}

	if (int res{bpfDiscoveryResumeCollecting()}) {
		throw std::runtime_error("Failed to set config of BPF program: " + std::to_string(res));
	}
}

void Discovery::unload() noexcept {
	if (bpf_obj != nullptr) {
		discovery_bpf__destroy(bpf_obj);
	}
	cleanup_core_btf(&bpf_open_opts);
}

void Discovery::stopRun() {
	running = false;
}

void Discovery::handleSuccessfulParse(const Session& session, const DiscoverySessionMeta& meta) {
	printSession(session, meta);
}

void Discovery::saveSession(const DiscoverySavedSessionKey& session_key, const Session& session) {
	savedSessions.insert(session_key, session);
}

int Discovery::bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& tracked_session_key) {
	return bpf_map__delete_elem(bpf_obj->maps.trackedSessionsMap, &tracked_session_key, sizeof(tracked_session_key), BPF_ANY);
}

} // namespace ebpfdiscovery
