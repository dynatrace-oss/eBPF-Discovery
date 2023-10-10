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
	if (const auto& xForwardedFor{request.xForwardedFor}; !xForwardedFor.empty()) {
		std::cout << " X-Forwarded-For: " << '"' << xForwardedFor << '"';
	} else if (discoverySessionFlagsIsIPv4(meta.flags)) {
		if (auto srcIpv4{ipv4ToString(meta.sourceIPData)}; !srcIpv4.empty())
			std::cout << " srcIpv4: " << '"' << srcIpv4 << '"';
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		if (auto srcIpv6{ipv6ToString(meta.sourceIPData)}; !srcIpv6.empty())
			std::cout << " srcIpv6: " << '"' << srcIpv6 << '"';
	}
	std::cout << " pid: " << meta.pid << '\n';
}

Discovery::Discovery() : Discovery(DiscoveryConfig{}) {
}

Discovery::Discovery(const DiscoveryConfig config) : savedSessions(DISCOVERY_MAX_SESSIONS) {
}

Discovery::~Discovery() {
	unload();
}

int Discovery::run() {
	if (!isLoaded()) {
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
	while (bpf_map__lookup_and_delete_elem(discoverySkel->maps.eventsToUserspaceQueueMap, NULL, 0, &event, sizeof(event), BPF_ANY) == 0) {
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
			discoverySkel->maps.savedBuffersMap,
			&event.dataKey,
			sizeof(DiscoverySavedBufferKey),
			&savedBuffer,
			sizeof(savedBuffer),
			BPF_ANY)};
	if (lookup_result != 0) {
		return;
	}

	handleBufferLookupSuccess(savedBuffer, event);
}

void Discovery::handleBufferLookupSuccess(DiscoverySavedBuffer& savedBuffer, DiscoveryEvent& event) {
	std::string_view bufferView(savedBuffer.data, savedBuffer.length);
	bpf_map__delete_elem(discoverySkel->maps.savedBuffersMap, &event.dataKey, sizeof(DiscoverySavedBufferKey), BPF_ANY);

	auto it{savedSessions.find(event.dataKey)};
	if (it != savedSessions.end()) {
		handleExistingSession(it, bufferView, event);
		return;
	}

	handleNewSession(bufferView, event);
}

void Discovery::handleExistingSession(SavedSessionsCacheType::iterator it, std::string_view& bufferView, DiscoveryEvent& event) {
	savedSessions.update(it, [bufferView = std::move(bufferView)](auto& session) { session.parser.parse(std::move(bufferView)); });
	if (it->second.parser.isInvalidState()) {
		bpfDiscoveryDeleteSession(event.dataKey);
		savedSessions.erase(it);
		return;
	}

	if (!it->second.parser.isFinished()) {
		// We expect more data buffers to come
		return;
	}

	handleSuccessfulParse(it->second, event.sessionMeta);
	savedSessions.update(it, [](auto& session) { session.reset(); });
}

void Discovery::handleNewSession(std::string_view& bufferView, DiscoveryEvent& event) {
	Session session;
	session.parser.parse(std::move(bufferView));
	if (session.parser.isInvalidState()) {
		bpfDiscoveryDeleteSession(event.dataKey);
		return;
	}

	if (!session.parser.isFinished() && !discoveryEventFlagsIsNoMoreData(event.flags)) {
		saveSession(event.dataKey, std::move(session));
		return;
	}

	if (!session.parser.isFinished()) {
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
			discoverySkel->maps.globalStateMap, &zero, sizeof(zero), &discoveryGlobalState, sizeof(discoveryGlobalState), BPF_EXIST);
}

int Discovery::bpfDiscoveryResetConfig() {
	return bpfDiscoveryResumeCollecting();
}

bool Discovery::isLoaded() noexcept {
	return discoverySkel != nullptr && loaded;
}

void Discovery::load() {
	LIBBPF_OPTS(bpf_object_open_opts, openOpts);
	discoverySkelOpenOpts = openOpts;

	if (int res{ensure_core_btf(&openOpts)}) {
		throw std::runtime_error("Failed to fetch necessary BTF for CO-RE: " + std::string(strerror(-res)));
	}

	discoverySkel = discovery_bpf__open_opts(&openOpts);
	if (discoverySkel == nullptr) {
		throw std::runtime_error("Failed to open BPF object.");
	}

	if (int res{discovery_bpf__load(discoverySkel)}) {
		throw std::runtime_error("Failed to load BPF object: " + std::to_string(res));
	}

	if (int res{discovery_bpf__attach(discoverySkel)}) {
		throw std::runtime_error("Failed to attach BPF object: " + std::to_string(res));
	}

	if (int res{bpfDiscoveryResumeCollecting()}) {
		throw std::runtime_error("Failed to set config of BPF program: " + std::to_string(res));
	}

	loaded = true;
}

void Discovery::unload() noexcept {
	stopRun();
	loaded = false;
	if (discoverySkel != nullptr) {
		discovery_bpf__destroy(discoverySkel);
	}
	cleanup_core_btf(&discoverySkelOpenOpts);
}

void Discovery::stopRun() {
	running = false;
}

void Discovery::handleSuccessfulParse(const Session& session, const DiscoverySessionMeta& meta) {
	printSession(session, meta);
}

void Discovery::saveSession(const DiscoverySavedSessionKey& sessionKey, const Session& session) {
	savedSessions.insert(sessionKey, session);
}

int Discovery::bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& trackedSessionKey) {
	return bpf_map__delete_elem(discoverySkel->maps.trackedSessionsMap, &trackedSessionKey, sizeof(trackedSessionKey), BPF_ANY);
}

} // namespace ebpfdiscovery
