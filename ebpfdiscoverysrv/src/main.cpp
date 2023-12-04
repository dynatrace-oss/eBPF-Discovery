// SPDX-License-Identifier: GPL-2.0
#include "ebpfdiscovery/Discovery.h"
#include "ebpfdiscovery/DiscoveryBpf.h"
#include "ebpfdiscovery/DiscoveryBpfLogging.h"
#include "logging/Logger.h"

#include <boost/asio/steady_timer.hpp>
#include <boost/program_options.hpp>

#include <atomic>
#include <filesystem>
#include <iostream>
#include <memory>
#include <signal.h>
#include <sstream>
#include <unistd.h>

namespace po = boost::program_options;
namespace bpflogging = ebpfdiscovery::bpflogging;
using logging::Logger;
using logging::LogLevel;

static std::atomic_flag programRunningFlag{ATOMIC_FLAG_INIT};

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
	Logger::getInstance().init("eBPF-Discovery", enableStdout, logDir);
	Logger::getInstance().setLevel(logLevel);
	LOG_TRACE("Logging has been set up. (enableStdout: {}, logDir: `{}`)", enableStdout, logDir.string());
}

static void handleUnixShutdownSignal(int signal) {
	programRunningFlag.clear();
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

template <typename Duration>
static void scheduleFunction(
		boost::asio::io_context& ioContext, boost::asio::steady_timer& timer, Duration interval, std::function<void()> func) {
	timer.expires_from_now(interval);
	timer.async_wait([&ioContext, &timer, interval, func](const boost::system::error_code& err) {
		if (err) {
			return;
		}
		func();
		scheduleFunction(ioContext, timer, interval, func);
	});
}

int main(int argc, char** argv) {
	programRunningFlag.test_and_set();
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

	boost::asio::io_context ioContext;
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
	}

	if (isLaunchTest) {
		programRunningFlag.clear();
	}

	int logPerfBufFd{discoveryBpf.getLogPerfBufFd()};

	perf_buffer* logBuf{bpflogging::setup(logPerfBufFd)};
	if (logBuf == nullptr) {
		LOG_CRITICAL("Could not open perf buffer for Discovery BPF logging: {}.", std::strerror(-errno));
	}

	auto eventQueuePollInterval{std::chrono::milliseconds(250)};
	auto fetchAndHandleTimer{boost::asio::steady_timer(ioContext, eventQueuePollInterval)};
	scheduleFunction(ioContext, fetchAndHandleTimer, eventQueuePollInterval, [&instance]() {
		auto ret{instance.fetchAndHandleEvents()};
		if (ret != 0) {
			LOG_CRITICAL("Failed to fetch and handle Discovery BPF events: {}.", std::strerror(-ret));
			programRunningFlag.clear();
		}
	});

	auto outputServicesToStdoutInterval{std::chrono::seconds(vm["interval"].as<int>())};
	auto outputServicesToStdoutTimer{boost::asio::steady_timer(ioContext, outputServicesToStdoutInterval)};
	scheduleFunction(ioContext, outputServicesToStdoutTimer, outputServicesToStdoutInterval, [&]() { instance.outputServicesToStdout(); });

	auto logBufFetchInterval{std::chrono::milliseconds(250)};
	auto logBufFetchTimer{boost::asio::steady_timer(ioContext, logBufFetchInterval)};
	if (logLevel <= logging::LogLevel::Debug) {
		LOG_DEBUG("Handling of Discovery BPF logging is enabled.");
		scheduleFunction(ioContext, logBufFetchTimer, logBufFetchInterval, [&]() {
			auto ret{bpflogging::fetchAndLog(logBuf)};
			if (ret != 0) {
				LOG_CRITICAL("Failed to fetch and handle Discovery BPF logging: {}.", std::strerror(-ret));
				programRunningFlag.clear();
			}
		});
	}

	while (programRunningFlag.test_and_set()) {
		ioContext.run_one();
	}
	programRunningFlag.clear();

	LOG_DEBUG("Exiting the program.");
	discoveryBpf.unload();
	bpflogging::close(logBuf);

	return EXIT_SUCCESS;
}
