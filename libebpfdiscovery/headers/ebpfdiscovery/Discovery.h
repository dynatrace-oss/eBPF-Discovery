// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ebpfdiscovery/DiscoveryBpf.h"
#include "ebpfdiscovery/LRUCache.h"
#include "ebpfdiscovery/Session.h"
#include "ebpfdiscoveryshared/Types.h"
#include "httpparser/HttpRequestParser.h"
#include "service/Aggregator.h"
#include "service/IpAddressChecker.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>

namespace ebpfdiscovery {

using httpparser::HttpRequestParser;

class Discovery {
public:
	Discovery(DiscoveryBpfFds bpfFds);
	Discovery(const Discovery&) = delete;
	Discovery& operator=(const Discovery&) = delete;
	~Discovery() = default;

	void init();

	int fetchAndHandleEvents();
	void outputServicesToStdout();

private:
	using SavedSessionsCacheType = LRUCache<DiscoverySavedSessionKey, Session, DiscoverySavedSessionKeyHash>;

	void handleNewEvent(DiscoveryEvent event);
	void saveSession(const DiscoverySavedSessionKey& session_key, const Session& session);

	void handleNewDataEvent(DiscoveryEvent& event);
	void handleCloseEvent(DiscoveryEvent& event);

	void handleBufferLookupSuccess(DiscoverySavedBuffer& savedBuffer, DiscoveryEvent& event);
	void handleExistingSession(SavedSessionsCacheType::iterator it, std::string_view& bufferView, DiscoveryEvent& event);
	void handleNewSession(std::string_view& bufferView, DiscoveryEvent& event);
	void handleNewRequest(const Session& session, const DiscoverySessionMeta& meta);
	void handleSuccessfulParse(const Session& session, const DiscoverySessionMeta& sessionMeta);

	int bpfDiscoveryFetchAndHandleEvents();
	int bpfDiscoveryResetConfig();
	int bpfDiscoveryResumeCollecting();
	int bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& trackedSessionKey);

	DiscoveryBpfFds bpfFds;

	SavedSessionsCacheType savedSessions;
	service::NetlinkCalls netlinkCalls;
	service::IpAddressChecker ipChecker{{}, netlinkCalls};
	service::Aggregator serviceAggregator{ipChecker};
};

} // namespace ebpfdiscovery
