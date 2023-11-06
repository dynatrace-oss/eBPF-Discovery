// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ebpfdiscovery/Config.h"
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
	Discovery(DiscoveryBpf discoveryBpf);
	Discovery(DiscoveryBpf discoveryBpf, const DiscoveryConfig config);
	Discovery(const Discovery&) = delete;
	Discovery& operator=(const Discovery&) = delete;
	Discovery(Discovery&&) = default;
	Discovery& operator=(Discovery&&) = default;
	~Discovery() = default;

	void start();
	void stop();
	void wait();

	std::vector<service::Service> popServices();

private:
	using SavedSessionsCacheType = LRUCache<DiscoverySavedSessionKey, Session, DiscoverySavedSessionKeyHash>;

	void run();

	void fetchEvents();
	void saveSession(const DiscoverySavedSessionKey& session_key, const Session& session);

	void handleNewEvent(DiscoveryEvent event);

	void handleNewDataEvent(DiscoveryEvent& event);
	void handleBufferLookupSuccess(DiscoverySavedBuffer& savedBuffer, DiscoveryEvent& event);
	void handleExistingSession(SavedSessionsCacheType::iterator it, std::string_view& bufferView, DiscoveryEvent& event);
	void handleNewSession(std::string_view& bufferView, DiscoveryEvent& event);
	void handleNewRequest(const Session& session, const DiscoverySessionMeta& meta);
	void handleCloseEvent(DiscoveryEvent& event);
	void handleSuccessfulParse(const Session& session, const DiscoverySessionMeta& sessionMeta);

	int bpfDiscoveryResetConfig();
	int bpfDiscoveryResumeCollecting();
	int bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& trackedSessionKey);

	constexpr auto discoverySkel() const {
		return discoveryBpf.skel;
	}

	DiscoveryConfig config;
	DiscoveryBpf discoveryBpf;
	SavedSessionsCacheType savedSessions;
	service::NetlinkCalls netlinkCalls;
	service::IpAddressChecker ipChecker{{}, netlinkCalls};
	service::Aggregator serviceAggregator{ipChecker};

	std::atomic<bool> running{false};
	bool stopReceived{false};
	std::condition_variable stopReceivedCV;
	std::mutex stopReceivedMutex;
	std::thread workerThread;
};

} // namespace ebpfdiscovery
