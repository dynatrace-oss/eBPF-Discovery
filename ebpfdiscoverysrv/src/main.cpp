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

#include "ebpfdiscovery/BpfOptions.h"
#include "ebpfdiscovery/Discovery.h"
#include "ebpfdiscovery/DiscoveryBpfLogging.h"
#include "ebpfdiscovery/ServiceDetectionTask.h"
#include "ebpfdiscovery/Slp.h"
#include "ebpfdiscovery/SlpDetectionTask.h"
#include "logging/Logger.h"

#include <boost/program_options.hpp>

#include <filesystem>
#include <iostream>
#include <csignal>
#include <future>
#include <chrono>

#include <sys/stat.h>

namespace po = boost::program_options;
using logging::Logger;
using logging::LogLevel;

namespace {

ebpfdiscovery::SlpDetectionTask slpBpfProg{};
ebpfdiscovery::ServiceDetectionTask servicesBpfProg{};

constexpr std::string_view testLaunchName = "test-launch";
constexpr std::string_view logDirName = "log-dir";
constexpr std::string_view logLevelName = "log-level";
constexpr std::string_view logNoStdoutName = "log-no-stdout";
constexpr std::string_view versionName = "version";
constexpr std::string_view enableServiceDetectionName = "enable-service-detection";
constexpr std::string_view intervalName = "interval";
constexpr std::string_view enableNetworkCountersName = "enable-network-counters";
constexpr std::string_view enableSlpName = "enable-slp";
constexpr std::string_view slpIntervalName = "slp-interval";

void stopRunningPrograms() {
	slpBpfProg.stop();
	servicesBpfProg.stop();
}

po::options_description getProgramOptions() {
	po::options_description desc{"Options"};

	// clang-format off
	desc.add_options()
	  ("help,h", "Display available options")
	  (testLaunchName.data(), po::bool_switch()->default_value(false), "Exit program after launching for testing")
	  (logDirName.data(), po::value<std::filesystem::path>()->default_value(""), "Log files directory")
	  (logLevelName.data(), po::value<logging::LogLevel>()->default_value(logging::LogLevel::Err, "error"), "Set log level {trace,debug,info,warning,error,critical,off}")
	  (logNoStdoutName.data(), po::bool_switch()->default_value(false), "Disable logging to stdout")
	  (versionName.data(), "Display program version")
	  //TODO change default value to false after DT OA starts using this switch for service detection
	  (enableServiceDetectionName.data(), po::bool_switch()->default_value(true), "Enables service detection")
	  (intervalName.data(), po::value<int>()->default_value(60), "Services reporting time interval (in seconds)")
	  (enableNetworkCountersName.data(), po::bool_switch()->default_value(false), "Enable network counters")
	  (enableSlpName.data(), po::bool_switch()->default_value(false), "Enables the short-lived-process detection")
	  (slpIntervalName.data(), po::value<int>()->default_value(60), "Short-lived-processes reporting time interval (in seconds)")
  ;
	// clang-format on

	return desc;
}

void initLogging(logging::LogLevel logLevel, bool enableStdout, const std::filesystem::path& logDir) {
	umask(S_IRWXG | S_IRWXO);
	Logger::getInstance().init(enableStdout, logDir);
	Logger::getInstance().setLevel(logLevel);
	LOG_TRACE("Logging has been set up. (enableStdout: {}, logDir: `{}`)", enableStdout, logDir.string());
}

void handleUnixShutdownSignal(int signal) {
	stopRunningPrograms();
}

int libbpfPrintFn(enum libbpf_print_level level, const char* format, va_list args) {
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

void initLibbpf() {
	libbpf_set_print(libbpfPrintFn);
}

}

int main(int argc, char** argv) {
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

	if (vm.count(versionName.data())) {
		std::cout << "eBPF-Discovery " << PROJECT_VERSION << '\n';
		return EXIT_SUCCESS;
	}

	const bool enableSlp{vm[enableSlpName.data()].as<bool>()};
	//TODO !enableSlp is a temporary workaround to allow gathering only slp, remove when changing enableServiceDetection default value to false
	const bool enableServiceDetection = !enableSlp && vm[enableServiceDetectionName.data()].as<bool>();

	if (!enableSlp && !enableServiceDetection) {
		return EXIT_SUCCESS;
	}

	LogLevel logLevel{vm[logLevelName.data()].as<LogLevel>()};
	bool isStdoutLogDisabled{vm[logNoStdoutName.data()].as<bool>()};
	std::filesystem::path logDir{vm[logDirName.data()].as<std::filesystem::path>()};

	try {
		initLogging(logLevel, !isStdoutLogDisabled, logDir);
	} catch (const std::runtime_error& e) {
		std::cerr << "Couldn't init logging: " << e.what() << '\n';
		return EXIT_FAILURE;
	}

	LOG_DEBUG("Starting the program.");

	initLibbpf();
	ebpfdiscovery::BpfOptions loadOptions;
	try {
		loadOptions.acquire();
	} catch (const std::runtime_error& e) {
		LOG_CRITICAL("Couldn't get bpf load options. ({})", e.what());
		return EXIT_FAILURE;
	}


	if (enableServiceDetection) {
		try {
			auto outputServicesToStdoutInterval{std::chrono::seconds(vm[intervalName.data()].as<int>())};
			const bool enableNetworkCounters{vm[enableNetworkCountersName.data()].as<bool>()};
			servicesBpfProg.start(loadOptions.getOpenOpts(), enableNetworkCounters, outputServicesToStdoutInterval, logLevel);
		} catch (const std::runtime_error& e) {
			LOG_CRITICAL("Couldn't load BPF program. ({})", e.what());
			return EXIT_FAILURE;
		}
	}

	if (enableSlp) {
		try {
			LOG_DEBUG("Starting SLP discovery.");
			auto slpInterval{std::chrono::seconds(vm[slpIntervalName.data()].as<int>())};
			slpBpfProg.start(loadOptions.getOpenOpts(), slpInterval);
		} catch (const std::runtime_error& e) {
			LOG_CRITICAL("Couldn't initialize Slp: {}", e.what());
			return EXIT_FAILURE;
		}
	}

	if (vm[testLaunchName.data()].as<bool>()) {
		stopRunningPrograms();
	}

	servicesBpfProg.waitForFinish();
	slpBpfProg.waitForFinish();

	LOG_DEBUG("Exiting the program.");
	servicesBpfProg.shutdown();
	slpBpfProg.shutdown();
	loadOptions.release();

	return EXIT_SUCCESS;
}
