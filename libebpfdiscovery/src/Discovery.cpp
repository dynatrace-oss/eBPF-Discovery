// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/Discovery.h"

#include "ebpfdiscovery/Session.h"
#include "ebpfdiscoveryproto/Translator.h"
#include "logging/Logger.h"
#include "service/IpAddress.h"

#include <bpf/bpf.h>

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

Discovery::Discovery(DiscoveryBpfFds bpfFds) : bpfFds(bpfFds), savedSessions(DISCOVERY_MAX_SESSIONS) {
}

void Discovery::init() {
	if (int ret{bpfDiscoveryResetConfig()}; ret != 0) {
		throw std::runtime_error("Could not initialize BPF program configuration: " + std::to_string(ret));
	}
}

int Discovery::fetchAndHandleEvents() {
	if (auto ret{bpfDiscoveryResumeCollecting()}; ret != 0) {
		return ret;
	}

	if (auto ret{bpfDiscoveryFetchAndHandleEvents()}; ret != 0) {
		return ret;
	}

	return 0;
}

void Discovery::outputServicesToStdout() {
	const auto services{serviceAggregator.collectServices()};
	if (services.empty()) {
		return;
	}

	const auto servicesProto{proto::internalToProto(services)};
	const auto servicesJson{proto::protoToJson(servicesProto)};
	std::cout << servicesJson << std::endl;
	serviceAggregator.clear();
}

int Discovery::bpfDiscoveryFetchAndHandleEvents() {
	DiscoveryEvent event;
	int ret;
	for (;;) {
		ret = bpf_map_lookup_and_delete_elem(bpfFds.eventsToUserspaceQueueMap, nullptr, &event);
		if (ret != 0) {
			break;
		}

		handleNewEvent(std::move(event));
	};

	if (ret != -ENOENT) {
		return ret;
	}

	return 0;
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
	auto res{bpf_map_lookup_and_delete_elem(bpfFds.savedBuffersMap, &event.dataKey, &savedBuffer)};
	if (res != 0) {
		return;
	}

	handleBufferLookupSuccess(savedBuffer, event);
}

void Discovery::handleBufferLookupSuccess(DiscoverySavedBuffer& savedBuffer, DiscoveryEvent& event) {
	std::string_view bufferView(savedBuffer.data, savedBuffer.length);
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
	const auto xForwardedForClient{request.xForwardedFor.empty() ? "" : ", X-Forwarded-For client: " + request.xForwardedFor.front()};
	if (discoverySessionFlagsIsIPv4(meta.flags)) {
		LOG_DEBUG(
				"Handling new request. (method: {}, host: {}, url: {}{}, sourceIPv4: {}, pid: {})",
				request.method,
				request.host,
				request.url,
				xForwardedForClient,
				service::ipv4ToString(meta.sourceIPData),
				meta.pid);
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		LOG_DEBUG(
				"Handling new request. (method: {}, host: {}, url: {}{}, sourceIPv6: {}, pid: {})",
				request.method,
				request.host,
				request.url,
				xForwardedForClient,
				service::ipv6ToString(meta.sourceIPData),
				meta.pid);
	} else {
		LOG_DEBUG(
				"Handling new request. (method: {}, host: {}, url: {}{}, pid: {})",
				request.method,
				request.host,
				request.url,
				xForwardedForClient,
				meta.pid);
	}
	serviceAggregator.newRequest(request, meta);
}

void Discovery::handleCloseEvent(DiscoveryEvent& event) {
	if (auto it{savedSessions.find(event.dataKey)}; it != savedSessions.end()) {
		savedSessions.erase(it);
	}
}

int Discovery::bpfDiscoveryResumeCollecting() {
	static uint32_t zero{0};
	DiscoveryGlobalState discoveryGlobalState{};
	return bpf_map_update_elem(bpfFds.globalStateMap, &zero, &discoveryGlobalState, BPF_EXIST);
}

int Discovery::bpfDiscoveryResetConfig() {
	return bpfDiscoveryResumeCollecting();
}

void Discovery::handleSuccessfulParse(const Session& session, const DiscoverySessionMeta& meta) {
	handleNewRequest(session, meta);
}

void Discovery::saveSession(const DiscoverySavedSessionKey& sessionKey, const Session& session) {
	savedSessions.insert(sessionKey, session);
}

int Discovery::bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& trackedSessionKey) {
	return bpf_map_delete_elem(bpfFds.trackedSessionsMap, &trackedSessionKey);
}

} // namespace ebpfdiscovery
