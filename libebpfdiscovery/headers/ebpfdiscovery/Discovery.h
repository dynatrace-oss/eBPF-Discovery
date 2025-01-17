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

#pragma once

#include "ebpfdiscovery/DiscoveryBpf.h"
#include "ebpfdiscovery/LRUCache.h"
#include "ebpfdiscovery/Session.h"
#include "ebpfdiscoveryshared/Types.h"
#include "httpparser/HttpRequestParser.h"
#include "service/Aggregator.h"
#include "service/IpAddressCheckerImpl.h"

#include <string_view>

namespace ebpfdiscovery {

using httpparser::HttpRequestParser;

class Discovery {
public:
	Discovery(const DiscoveryBpfFds& bpfFds, const bool _enableNetworkCounters);
	Discovery(const Discovery&) = delete;
	Discovery& operator=(const Discovery&) = delete;

	void init();

	int fetchAndHandleEvents();
	void outputServicesToStdout();

	void networkCountersCleaning();

private:
	using SavedSessionsCacheType = LRUCache<DiscoverySavedSessionKey, Session, DiscoverySavedSessionKeyHash>;

	void handleNewEvent(DiscoveryEvent event);
	void saveSession(const DiscoverySavedSessionKey& session_key, const Session& session);

	void handleNewDataEvent(DiscoveryEvent& event);
	void handleCloseEvent(DiscoveryEvent& event);

	void handleBufferLookupSuccess(DiscoverySavedBuffer& savedBuffer, DiscoveryEvent& event);
	void handleExistingSession(SavedSessionsCacheType::iterator it, std::string_view& bufferView, DiscoveryEvent& event);
	void handleNewSession(std::string_view& bufferView, DiscoveryEvent& event);
	void handleNewRequest(const Session& session, const service::DiscoverySessionMeta& meta);
	void handleSuccessfulParse(const Session& session, const service::DiscoverySessionMeta& sessionMeta);

	int bpfDiscoveryFetchAndHandleEvents();
	int bpfDiscoveryResetConfig();
	int bpfDiscoveryResumeCollecting();
	int bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& trackedSessionKey);

	DiscoveryBpfFds bpfFds;

	SavedSessionsCacheType savedSessions;
	service::InterfacesReader interfacesReader;
	service::IpAddressCheckerImpl ipChecker{interfacesReader};
	service::Aggregator serviceAggregator;
};

} // namespace ebpfdiscovery
