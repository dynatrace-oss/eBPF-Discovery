// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <iostream>

#include "ebpfdiscovery/Config.h"
#include "ebpfdiscovery/DiscoveryBpf.h"
#include "ebpfdiscovery/LRUCache.h"
#include "ebpfdiscovery/Session.h"
#include "ebpfdiscoveryshared/Types.h"
#include "httpparser/HttpRequestParser.h"

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
	void wait();
	void stop();

private:
	typedef LRUCache<DiscoverySavedSessionKey, Session, DiscoverySavedSessionKeyHash> SavedSessionsCacheType;

	void run();
	void stopRun();

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

	DiscoveryBpf discoveryBpf;
	DiscoveryConfig config;
	SavedSessionsCacheType savedSessions;
	bool running;
	std::mutex runningMutex;
	std::thread runningThread;
	std::condition_variable runningCV;
};

} // namespace ebpfdiscovery
