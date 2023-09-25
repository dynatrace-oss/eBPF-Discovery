// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ebpfdiscovery/Config.h"
#include "ebpfdiscovery/LRUCache.h"
#include "ebpfdiscovery/Session.h"
#include "ebpfdiscoveryshared/Types.h"
#include "httpparser/HttpRequestParser.h"

#include "discovery.skel.h"

#include <atomic>
#include <chrono>
#include <queue>
#include <string>
#include <unordered_map>

namespace ebpfdiscovery {

using httpparser::HttpRequestParser;

class Discovery {
public:
	Discovery();
	Discovery(const DiscoveryConfig config);
	~Discovery();

	bool isLoaded() noexcept;
	void load();
	void unload() noexcept;

	// Blocks current thread until stopRun() is called
	int run();

	// Thread safe operation
	void stopRun();

private:
	typedef LRUCache<DiscoverySavedSessionKey, Session, DiscoverySavedSessionKeyHash> SavedSessionsCacheType;

	void fetchEvents();
	void saveSession(const DiscoverySavedSessionKey& session_key, const Session& session);

	void handleNewEvent(DiscoveryEvent event);

	void handleNewDataEvent(DiscoveryEvent& event);
	void handleBufferLookupSuccess(DiscoverySavedBuffer& savedBuffer, DiscoveryEvent& event);
	void handleExistingSession(SavedSessionsCacheType::iterator it, std::string_view& bufferView, DiscoveryEvent& event);
	void handleNewSession(std::string_view& bufferView, DiscoveryEvent& event);
	void handleCloseEvent(DiscoveryEvent& event);
	void handleSuccessfulParse(const Session& session, const DiscoverySessionMeta& sessionMeta);

	int bpfDiscoveryResetConfig();
	int bpfDiscoveryResumeCollecting();
	int bpfDiscoveryDeleteSession(const DiscoveryTrackedSessionKey& trackedSessionKey);

	DiscoveryConfig config;

	std::atomic<bool> running;
	std::atomic<bool> loaded;
	discovery_bpf* discoverySkel;
	bpf_object_open_opts discoverySkelOpenOpts;
	SavedSessionsCacheType savedSessions;
};

} // namespace ebpfdiscovery
