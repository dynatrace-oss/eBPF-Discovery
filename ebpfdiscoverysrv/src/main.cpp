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
#include "ebpfdiscovery/DiscoveryBpf.h"
#include "ebpfdiscovery/DiscoveryBpfLogging.h"
#include "logging/Logger.h"

#include <boost/program_options.hpp>

#include <atomic>
#include <filesystem>
#include <iostream>
#include <csignal>
#include <future>
#include <chrono>
#include <thread>

#include <sys/stat.h>

namespace po = boost::program_options;
namespace bpflogging = ebpfdiscovery::bpflogging;
using logging::Logger;
using logging::LogLevel;

static std::atomic<bool> programRunningFlag = false;
std::mutex mutex;
std::condition_variable cv;

static po::options_description getProgramOptions() {
	po::options_description desc{"Options"};

	// clang-format off
	desc.add_options()
      ("help,h", "Display available options")
      ("test-launch", po::bool_switch()->default_value(false), "Exit program after launching for testing")
      ("log-dir", po::value<std::filesystem::path>()->default_value(""), "Log files directory")
      ("log-level", po::value<logging::LogLevel>()->default_value(logging::LogLevel::Err, "error"), "Set log level {trace,debug,info,warning,error,critical,off}")
      ("log-no-stdout", po::bool_switch()->default_value(false), "Disable logging to stdout")
      ("version", "Display program version")
      ("interval", po::value<int>()->default_value(60), "Services reporting time interval (in seconds)")
  ;
	// clang-format on

	return desc;
}

static void initLogging(logging::LogLevel logLevel, bool enableStdout, const std::filesystem::path& logDir) {
	umask(S_IRWXG | S_IRWXO);
	Logger::getInstance().init(enableStdout, logDir);
	Logger::getInstance().setLevel(logLevel);
	LOG_TRACE("Logging has been set up. (enableStdout: {}, logDir: `{}`)", enableStdout, logDir.string());
}

static void handleUnixShutdownSignal(int signal) {
	programRunningFlag = false;
	cv.notify_all();
}

static int libbpfPrintFn(enum libbpf_print_level level, const char* format, va_list args) {
	switch (level) {
	case LIBBPF_WARN:
		Logger::getInstance().vlogf(logging::LogLevel::Warn, format, args);
		return 0;
	case LIBBPF_INFO:
		Logger::getInstance().vlogf(logging::LogLevel::Info, format, args);
		return 0;
	case LIBBPF_DEBUG:
		Logger::getInstance().vlogf(logging::LogLevel::Trace, format, args);
		return 0;
	}
	return 0;
}

static void initLibbpf() {
	libbpf_set_print(libbpfPrintFn);
}

static void periodicTask(const std::chrono::milliseconds interval, std::function<void()> func) {
	while (programRunningFlag) {
		func();
		{
			std::unique_lock ul(mutex);
			cv.wait_for(ul, interval, [] { return !programRunningFlag; });
		}
	}
}

template <typename Duration>
static std::future<void> setupBpfLogging(logging::LogLevel logLevel, Duration logBufFetchInterval, perf_buffer* logBuf){
	if (logLevel <= logging::LogLevel::Debug) {
		LOG_DEBUG("Handling of Discovery BPF logging is enabled.");
		return std::async(std::launch::async, periodicTask, logBufFetchInterval, [logBuf]() {
			auto ret{bpflogging::fetchAndLog(logBuf)};
			if (ret != 0) {
				LOG_CRITICAL("Failed to fetch and handle Discovery BPF logging: {}.", std::strerror(-ret));
				programRunningFlag = false;
			}
		});
	}
	return {};
}

int main(int argc, char** argv) {
	programRunningFlag = true;
	std::signal(SIGINT, handleUnixShutdownSignal);
	std::signal(SIGPIPE, handleUnixShutdownSignal);
	std::signal(SIGTERM, handleUnixShutdownSignal);

	po::options_description desc{getProgramOptions()};
	po::variables_map vm;

	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	} catch (const po::error& e) {
		std::cout << e.what() << '\n';
		return EXIT_FAILURE;
	}

	if (vm.count("help")) {
		std::cout << desc;
		return EXIT_SUCCESS;
	}

	if (vm.count("version")) {
		std::cout << "eBPF-Discovery " << PROJECT_VERSION << '\n';
		return EXIT_SUCCESS;
	}

	logging::LogLevel logLevel{vm["log-level"].as<logging::LogLevel>()};
	bool isStdoutLogDisabled{vm["log-no-stdout"].as<bool>()};
	std::filesystem::path logDir{vm["log-dir"].as<std::filesystem::path>()};
	bool isLaunchTest{vm["test-launch"].as<bool>()};

	try {
		initLogging(logLevel, !isStdoutLogDisabled, logDir);
	} catch (const std::runtime_error& e) {
		std::cerr << "Couldn't init logging: " << e.what() << '\n';
		return EXIT_FAILURE;
	}

	LOG_DEBUG("Starting the program.");

	initLibbpf();
	ebpfdiscovery::DiscoveryBpf discoveryBpf;
	try {
		discoveryBpf.load();
	} catch (const std::runtime_error& e) {
		LOG_CRITICAL("Couldn't load BPF program. ({})", e.what());
		return EXIT_FAILURE;
	}

	const auto bpfFds{discoveryBpf.getFds()};
	ebpfdiscovery::Discovery instance(bpfFds);
	try {
		instance.init();
	} catch (const std::runtime_error& e) {
		LOG_CRITICAL("Couldn't initialize Discovery: {}", e.what());
		return EXIT_FAILURE;
	}

	if (isLaunchTest) {
		programRunningFlag = false;
		cv.notify_all();
	}

	const int logPerfBufFd{discoveryBpf.getLogPerfBufFd()};

	perf_buffer* logBuf{bpflogging::setupLogging(logPerfBufFd)};
	if (logBuf == nullptr) {
		LOG_CRITICAL("Could not open perf buffer for Discovery BPF logging: {}.", std::strerror(-errno));
		return EXIT_FAILURE;
	}

	auto eventQueuePollInterval{std::chrono::milliseconds(250)};
	auto featchAndHandleEventsFuture = std::async(std::launch::async, periodicTask, eventQueuePollInterval, [&instance]() {
		auto ret{instance.fetchAndHandleEvents()};
		if (ret != 0) {
			LOG_CRITICAL("Failed to fetch and handle Discovery BPF events: {}.", std::strerror(-ret));
			programRunningFlag = false;
			cv.notify_all();
		}
	});

	auto outputServicesToStdoutInterval{std::chrono::seconds(vm["interval"].as<int>())};
	auto outputServicesToStdoutFuture = std::async(std::launch::async, periodicTask, outputServicesToStdoutInterval, [&](){ instance.outputServicesToStdout(); });

	auto logBufFetchInterval{std::chrono::milliseconds(250)};
	auto logBpfLoggingFuture = setupBpfLogging(logLevel, logBufFetchInterval, logBuf);

	if(outputServicesToStdoutFuture.valid()) {
		outputServicesToStdoutFuture.wait();
	}
	if(logBpfLoggingFuture.valid()) {
		logBpfLoggingFuture.wait();
	}
	if(featchAndHandleEventsFuture.valid()) {
		featchAndHandleEventsFuture.wait();
	}

	programRunningFlag = false;

	LOG_DEBUG("Exiting the program.");
	discoveryBpf.unload();
	bpflogging::closeLogging(logBuf);

	return EXIT_SUCCESS;
}
