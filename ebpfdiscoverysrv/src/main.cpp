// SPDX-License-Identifier: GPL-2.0
#include "ebpfdiscovery/Discovery.h"
#include "ebpfdiscovery/DiscoveryBpf.h"
#include "ebpfdiscovery/DiscoveryBpfLoader.h"
#include "logging/Global.h"

#include <bpf/libbpf.h>
#include <fmt/printf.h>

#include <iostream>
#include <memory>
#include <signal.h>
#include <unistd.h>

std::mutex shutdownFuncsMutex;
static std::atomic<bool> isShuttingDown;
std::vector<std::function<void()>> shutdownFuncs;

/*
 * Logging setup
 */

static void setupLogging() {
	logging::Global::getInstance().setup("eBPF-Discovery", true);
	logging::Global::getInstance().setLevel(logging::LogLevel::Trace);
	LOG_TRACE("Logging has been set up.");
}

/*
 * Unix signals setup
 */

static void shutdown() {
	if (isShuttingDown) {
		return;
	}
	std::unique_lock<std::mutex> lock(shutdownFuncsMutex);
	isShuttingDown = true;

	LOG_DEBUG("Exiting the program.");
	for (const auto& func : shutdownFuncs) {
		func();
	}
}

static void handleUnixExitSignal(int signo) {
	LOG_DEBUG("Handling unix exit signal.");
	shutdown();
}

static void setupUnixSignalHandlers() {
	struct sigaction action {};
	action.sa_handler = handleUnixExitSignal;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, nullptr);
	sigaction(SIGTERM, &action, nullptr);
	sigaction(SIGPIPE, &action, nullptr);
}

/*
 * Libbpf setup
 */

static int libbpfPrintFn(enum libbpf_print_level level, const char* format, va_list args) {
	switch (level) {
	case LIBBPF_WARN:
		logging::Global::getInstance().vlogf(logging::LogLevel::Warn, format, args);
		return 0;
	case LIBBPF_INFO:
		logging::Global::getInstance().vlogf(logging::LogLevel::Info, format, args);
		return 0;
	case LIBBPF_DEBUG:
		logging::Global::getInstance().vlogf(logging::LogLevel::Debug, format, args);
		return 0;
	}
	return 0;
}

static void setupLibbpf() {
	libbpf_set_print(libbpfPrintFn);
}

int main(int argc, char** argv) {
	setupUnixSignalHandlers();
	setupLogging();
	setupLibbpf();

	ebpfdiscovery::DiscoveryBpfLoader loader;
	try {
		loader.load();
	} catch (const std::runtime_error& e) {
		LOG_CRITICAL("Couldn't load BPF program. ({})", e.what());
		return EXIT_FAILURE;
	}

	ebpfdiscovery::Discovery instance(loader.get());

	{
		std::unique_lock<std::mutex> lock(shutdownFuncsMutex);
		shutdownFuncs.push_back([&instance]() { instance.stop(); });
	}

	if (isShuttingDown) {
		return EXIT_SUCCESS;
	}

	instance.start();

	instance.wait();
	shutdown();

	return EXIT_SUCCESS;
}
