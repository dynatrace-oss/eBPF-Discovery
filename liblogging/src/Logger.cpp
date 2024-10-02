/*
 * Copyright 2024 Dynatrace LLC
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

#include "logging/Logger.h"

#include "Formatting.h"

#include <boost/algorithm/string.hpp>
#include <spdlog/common.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdarg>
#include <filesystem>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

namespace logging {

std::istream& operator>>(std::istream& in, LogLevel& level) {
	std::string token;
	in >> token;
	std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c) { return std::tolower(c); });
	if (token == "trace") {
		level = LogLevel::Trace;
	} else if (token == "debug") {
		level = LogLevel::Debug;
	} else if (token == "info") {
		level = LogLevel::Info;
	} else if (token == "warning" || token == "warn") {
		level = LogLevel::Warn;
	} else if (token == "error" || token == "err") {
		level = LogLevel::Err;
	} else if (token == "critical" || token == "crit") {
		level = LogLevel::Critical;
	} else if (token == "off") {
		level = LogLevel::Off;
	} else {
		in.setstate(std::ios::failbit);
	}
	return in;
}

Logger::Logger() : spdLogger("") {
	loggerSetDefaults();
}

Logger& Logger::getInstance() {
	static Logger instance;
	return instance;
}

void Logger::setLevel(enum LogLevel level) {
	spdLogger.set_level(static_cast<spdlog::level::level_enum>(level));
}

void Logger::init(bool logToStdout, std::filesystem::path logDir) {
	namespace fs = std::filesystem;

	std::vector<spdlog::sink_ptr> sinks;
	if (logToStdout) {
		sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
	}

	if (!logDir.empty()) {
		if (!fs::exists(logDir)) {
			throw std::runtime_error("Log directory doesn't exist");
		}

		if (!fs::is_directory(logDir)) {
			throw std::runtime_error("Log directory is not a directory");
		}

		if (access(logDir.c_str(), R_OK | W_OK) != 0) {
			throw std::runtime_error("Couldn't access log directory for reading and writing");
		}

		const fs::path logFile{logDir / ("ebpf_discovery_" + std::to_string(getpid()) + ".log")};
		sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logFile, MAX_FILE_SIZE_IN_BYTES, MAX_FILES));
	}

	setLogger(spdlog::logger("ebpfdiscovery", sinks.begin(), sinks.end()));
}

void Logger::vlogf(enum LogLevel level, const char* format, va_list args) {
	if (!spdLogger.should_log(static_cast<spdlog::level::level_enum>(level))) {
		return;
	}

	auto formatted{logging::vaFormat(format, args)};
	if (formatted.empty()) {
		return;
	}

	boost::trim_right(formatted);
	log(level, "{}", formatted);
}

void Logger::setLogger(spdlog::logger logger) {
	spdLogger = std::move(logger);
	loggerSetDefaults();
}

void Logger::loggerSetDefaults() {
	spdLogger.set_level(spdlog::level::off);
	spdLogger.set_pattern("%Y-%m-%d %H:%M:%S.%e [%t] %^%l%$ [%n] %v");
}

} // namespace logging
