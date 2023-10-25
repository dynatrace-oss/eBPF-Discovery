// SPDX-License-Identifier: GPL-2.0
#include "ebpfdiscovery/Discovery.h"
#include "ebpfdiscovery/DiscoveryBpf.h"
#include "ebpfdiscovery/DiscoveryBpfLoader.h"
#include "ebpfdiscoveryproto/Translator.h"
#include "logging/Logger.h"

#include <boost/program_options.hpp>

#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <memory>
#include <signal.h>
#include <sstream>
#include <unistd.h>

namespace po = boost::program_options;
using logging::Logger;
using logging::LogLevel;

enum class ProgramStatus {
	Running,
	UnixShutdownSignalReceived,
} programStatus;

std::condition_variable programStatusCV;
std::mutex programStatusMutex;

/*
 * CLI options
 */

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

/*
 * Logging init
 */

static void initLogging(logging::LogLevel logLevel, bool enableStdout, const std::filesystem::path& logDir) {
	Logger::getInstance().init("eBPF-Discovery", enableStdout, logDir);
	Logger::getInstance().setLevel(logLevel);
	LOG_TRACE("Logging has been set up. (enableStdout: {}, logDir: `{}`)", enableStdout, logDir.string());
}

/*
 * Unix signals init
 */

static sigset_t getSigset() {
	sigset_t sigset;
	sigfillset(&sigset);
	return sigset;
}

static void runUnixSignalHandlerLoop() {
	while (true) {
		sigset_t sigset{getSigset()};
		LOG_TRACE("Waiting for unix signals.");
		const auto signo{sigwaitinfo(&sigset, nullptr)};
		if (signo == -1) {
			LOG_CRITICAL("Failed to wait for unix signals: {}", std::strerror(errno));
			std::abort();
		}
		LOG_DEBUG("Received unix signal. (signo: {})", signo);
		if (signo == SIGINT || signo == SIGPIPE || signo == SIGTERM) {
			std::lock_guard<std::mutex> lock(programStatusMutex);
			programStatus = ProgramStatus::UnixShutdownSignalReceived;
			LOG_TRACE("Unix signal handler is notifying for shutdown.");
			programStatusCV.notify_all();
			break;
		}
	}
}

/*
 * Libbpf init
 */

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

void servicesProvidingLoop(ebpfdiscovery::Discovery& discoveryInstance, std::chrono::seconds interval) {
	while (programStatus == ProgramStatus::Running) {
		if (auto services = discoveryInstance.popServices(); !services.empty()) {
			auto servicesProto = proto::internalToProto(services);
			LOG_DEBUG("Services list:\n{}\n", servicesProto.DebugString());
			auto servicesJson = proto::protoToJson(servicesProto);
			std::cout << servicesJson << std::endl;
		}
		std::this_thread::sleep_for(interval);
	}
}

int main(int argc, char** argv) {
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

	{
		LOG_TRACE("Setting up unix signals handling.");
		sigset_t sigset = getSigset();
		if (sigprocmask(SIG_BLOCK, &sigset, nullptr) == -1) {
			LOG_CRITICAL("Failed to block unix signals: {}", std::strerror(errno));
			return EXIT_FAILURE;
		}
	}

	initLibbpf();
	ebpfdiscovery::DiscoveryBpfLoader loader;
	try {
		loader.load();
	} catch (const std::runtime_error& e) {
		LOG_CRITICAL("Couldn't load BPF program. ({})", e.what());
		return EXIT_FAILURE;
	}

	ebpfdiscovery::Discovery instance(loader.get());
	try {
		instance.start();
	} catch (const std::runtime_error& e) {
		LOG_CRITICAL("Couldn't start Discovery: {}", e.what());
	}

	if (!isLaunchTest) {
		std::thread servicesProvider(servicesProvidingLoop, std::ref(instance), std::chrono::seconds(vm["interval"].as<int>()));
		std::thread unixSignalThread(runUnixSignalHandlerLoop);
		{
			std::unique_lock<std::mutex> programStatusLock(programStatusMutex);
			programStatusCV.wait(programStatusLock, []() { return programStatus != ProgramStatus::Running; });
		}

		LOG_TRACE("Waiting for unix signal thread to exit.");
		if (unixSignalThread.joinable()) {
			unixSignalThread.join();
		}
	}
	if (servicesProvider.joinable()) {
		servicesProvider.join();
	}

	LOG_DEBUG("Exiting the program.");
	instance.stop();

	LOG_TRACE("Waiting for threads to exit.");
	instance.wait();

	LOG_TRACE("Finished running the program successfully.");
	return EXIT_SUCCESS;
}
