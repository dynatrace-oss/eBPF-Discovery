/*
 * Copyright 2023 Dynatrace LLC
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
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

namespace ebpfdiscovery {

Discovery::Discovery(const DiscoveryBpfFds& bpfFds) : bpfFds{bpfFds}, savedSessions{DISCOVERY_MAX_SESSIONS} {
}

void Discovery::init() {
	if (const auto ret{bpfDiscoveryResetConfig()}; ret != 0) {
		throw std::runtime_error("Could not initialize BPF program configuration: " + std::to_string(ret));
	}
}

int Discovery::fetchAndHandleEvents() {
	if (const auto ret{bpfDiscoveryResumeCollecting()}; ret != 0) {
		return ret;
	}

	if (const auto ret{bpfDiscoveryFetchAndHandleEvents()}; ret != 0) {
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
	if (discoveryFlagsEventIsNewData(event.flags)) {
		handleNewDataEvent(event);
	}
	if (discoveryFlagsEventIsDataEnd(event.flags)) {
		handleCloseEvent(event);
	}
}

void Discovery::handleNewDataEvent(DiscoveryEvent& event) {
	DiscoverySavedBuffer savedBuffer;
	const auto res{bpf_map_lookup_and_delete_elem(bpfFds.savedBuffersMap, &event.key, &savedBuffer)};
	if (res != 0) {
		LOG_TRACE("No saved buffer for data event. (pid:{}, fd:{}, sessionID:{}, bufferSeq:{})", event.key.pid, event.key.fd, event.key.sessionID, event.key.bufferSeq);
		return;
	}

	handleBufferLookupSuccess(savedBuffer, event);
}

void Discovery::handleBufferLookupSuccess(DiscoverySavedBuffer& savedBuffer, DiscoveryEvent& event) {
	std::string_view bufferView(savedBuffer.data, savedBuffer.length);
	const auto it{savedSessions.find(event.key)};
	if (it != savedSessions.end()) {
		handleExistingSession(it, bufferView, event);
		return;
	}

	handleNewSession(bufferView, event);
}

void Discovery::handleExistingSession(SavedSessionsCacheType::iterator it, std::string_view& bufferView, DiscoveryEvent& event) {
	savedSessions.update(it, [bufferView = std::move(bufferView), flags = event.flags](auto& session) { session.parser.parse(std::move(bufferView), flags); });
	if (it->second.parser.isInvalidState()) {
		bpfDiscoveryDeleteSession(event.key);
		savedSessions.erase(it);
		return;
	}

	if (!it->second.parser.isFinished()) {
		// We expect more data buffers to come
		return;
	}

	service::DiscoverySessionMeta sessionMeta{.sourceIP = event.sourceIP, .pid = event.key.pid, .flags = event.flags};
	handleSuccessfulParse(it->second, sessionMeta);
	savedSessions.update(it, [](auto& session) { session.reset(); });
}

void Discovery::handleNewSession(std::string_view& bufferView, DiscoveryEvent& event) {
	Session session;
	session.parser.parse(std::move(bufferView), event.flags);
	if (session.parser.isInvalidState()) {
		return;
	}

	if (!session.parser.isFinished() && !discoveryFlagsEventIsDataEnd(event.flags)) {
		saveSession(event.key, std::move(session));
		return;
	}

	if (!session.parser.isFinished()) {
		return;
	}

	service::DiscoverySessionMeta sessionMeta{.sourceIP = event.sourceIP, .pid = event.key.pid, .flags = event.flags};
	handleSuccessfulParse(session, sessionMeta);
}

void Discovery::handleNewRequest(const Session& session, const service::DiscoverySessionMeta& meta) {
	const auto& request{session.parser.result};
	const auto xForwardedForClient{request.xForwardedFor.empty() ? "" : ", X-Forwarded-For client: " + request.xForwardedFor.front()};
	if (discoveryFlagsSessionIsIPv4(meta.flags)) {
		LOG_DEBUG(
				"Handling new request. (method: {}, host: {}, url: {}{}, sourceIPv4: {}, pid: {})",
				request.method,
				request.host,
				request.url,
				xForwardedForClient,
				service::ipv4ToString(meta.sourceIP.data),
				meta.pid);
	} else if (discoveryFlagsSessionIsIPv6(meta.flags)) {
		LOG_DEBUG(
				"Handling new request. (method: {}, host: {}, url: {}{}, sourceIPv6: {}, pid: {})",
				request.method,
				request.host,
				request.url,
				xForwardedForClient,
				service::ipv6ToString(meta.sourceIP.data),
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
	if (auto it{savedSessions.find(event.key)}; it != savedSessions.end()) {
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

void Discovery::handleSuccessfulParse(const Session& session, const service::DiscoverySessionMeta& meta) {
	handleNewRequest(session, meta);
}

void Discovery::saveSession(const DiscoverySavedSessionKey& sessionKey, const Session& session) {
	savedSessions.insert(sessionKey, session);
}

int Discovery::bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& trackedSessionKey) {
	return bpf_map_delete_elem(bpfFds.trackedSessionsMap, &trackedSessionKey);
}

} // namespace ebpfdiscovery
