// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/Discovery.h"

#include "StringFunctions.h"
#include "ebpfdiscovery/Session.h"
#include "logging/Global.h"

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

Discovery::Discovery(DiscoveryBpf discoveryBpf) : Discovery(discoveryBpf, DiscoveryConfig{}) {
}

Discovery::Discovery(DiscoveryBpf discoveryBpf, const DiscoveryConfig config)
		: discoveryBpf(discoveryBpf), savedSessions(DISCOVERY_MAX_SESSIONS) {
}

void Discovery::start() {
	runningThread = std::thread([this]() {
		this->run();
		runningCV.notify_all();
	});
}

void Discovery::stop() {
	stopRun();
	if (runningThread.joinable()) {
		runningThread.join();
	}
}

void Discovery::run() {
	std::unique_lock<std::mutex> lock(runningMutex);

	running = true;
	if (int ret{bpfDiscoveryResumeCollecting()}; ret != 0) {
		LOG_CRITICAL("{}", "Could not initialize BPF program configuration. (Return code: {})", ret);
		return;
	}
	while (running) {
		fetchEvents();
		bpfDiscoveryResumeCollecting();
		runningCV.wait_for(lock, config.eventQueuePollInterval);
	}

	return;
}

void Discovery::wait() {
	std::unique_lock<std::mutex> lock(runningMutex);
	runningCV.wait(lock, [this]() { return !running; });
}

void Discovery::fetchEvents() {
	DiscoveryEvent event;
	while (bpf_map__lookup_and_delete_elem(discoverySkel()->maps.eventsToUserspaceQueueMap, NULL, 0, &event, sizeof(event), BPF_ANY) == 0) {
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
			discoverySkel()->maps.savedBuffersMap,
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
	bpf_map__delete_elem(discoverySkel()->maps.savedBuffersMap, &event.dataKey, sizeof(DiscoverySavedBufferKey), BPF_ANY);

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

void Discovery::handleNewRequest(const Session& session, const DiscoverySessionMeta& meta) {
	const auto& request{session.parser.result};
	if (discoverySessionFlagsIsIPv4(meta.flags)) {
		LOG_DEBUG("Handling new request. (method:'{}', host:'{}', url:'{}', X-Forwarded-For:'{}', sourceIPv4:'{}')", request.method, request.host, request.url, request.xForwardedFor, ipv4ToString(meta.sourceIPData));
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		LOG_DEBUG("Handling new request. (method:'{}', host:'{}', url:'{}', X-Forwarded-For:'{}', sourceIPv6:'{}')", request.method, request.host, request.url, request.xForwardedFor, ipv6ToString(meta.sourceIPData));
	} else {
		LOG_DEBUG("Handling new request. (method:'{}', host:'{}', url:'{}', X-Forwarded-For:'{}')", request.method, request.host, request.url, request.xForwardedFor);
	}
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
			discoverySkel()->maps.globalStateMap, &zero, sizeof(zero), &discoveryGlobalState, sizeof(discoveryGlobalState), BPF_EXIST);
}

int Discovery::bpfDiscoveryResetConfig() {
	return bpfDiscoveryResumeCollecting();
}

void Discovery::stopRun() {
	std::lock_guard<std::mutex> lock(runningMutex);
	running = false;
}

void Discovery::handleSuccessfulParse(const Session& session, const DiscoverySessionMeta& meta) {
	handleNewRequest(session, meta);
}

void Discovery::saveSession(const DiscoverySavedSessionKey& sessionKey, const Session& session) {
	savedSessions.insert(sessionKey, session);
}

int Discovery::bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& trackedSessionKey) {
	return bpf_map__delete_elem(discoverySkel()->maps.trackedSessionsMap, &trackedSessionKey, sizeof(trackedSessionKey), BPF_ANY);
}

} // namespace ebpfdiscovery
