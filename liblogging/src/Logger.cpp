// SPDX-License-Identifier: Apache-2.0
#include "logging/Logger.h"

#include <spdlog/common.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdarg>
#include <filesystem>
#include <memory>
#include <string>
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

Logger::Logger() : spdLogger("default") {
	loggerSetDefaults();
}

void Logger::setLevel(enum LogLevel level) {
	spdLogger.set_level(static_cast<spdlog::level::level_enum>(level));
}

void Logger::setup(std::string name, bool logToStdout, const std::string_view& logDir) {
	namespace fs = std::filesystem;

	if (name.empty()) {
		name = "default";
	}

	std::vector<spdlog::sink_ptr> sinks;
	if (logToStdout) {
		sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
	}

	if (!logDir.empty()) {
		if (!fs::is_directory(logDir)) {
			throw std::runtime_error("Log directory doesn't exist or is not a directory");
		}
		// TODO: Check for permissions
		std::string logFile = fmt::format("{}/{}.log", logDir, name);
		sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logFile, max_size, max_files));
	}

	setLogger(spdlog::logger(name, sinks.begin(), sinks.end()));
}

void Logger::vlogf(enum LogLevel level, const char* format, va_list args) {
	if (!spdLogger.should_log(static_cast<spdlog::level::level_enum>(level))) {
		return;
	}
	const int staticBufSize = 512;
	static char staticBuf[staticBufSize]{};

	static va_list argsCopy;
	va_copy(argsCopy, args);

	int resultSize = vsnprintf(staticBuf, staticBufSize, format, args);
	if (resultSize <= staticBufSize) {
		logLine(level, staticBuf, resultSize);
		return;
	}

	char buf[resultSize]{};
	vsnprintf(buf, resultSize, format, argsCopy);

	logLine(level, buf, resultSize);
}

void Logger::setLogger(spdlog::logger logger) {
	spdLogger = std::move(logger);
	loggerSetDefaults();
}

void Logger::loggerSetDefaults() {
	spdLogger.set_level(spdlog::level::off);
	spdLogger.set_pattern("%Y-%m-%d %H:%M:%S.%e [%t] %^%l%$ [%n] %v");
}

void Logger::logLine(enum LogLevel level, const char* buf, size_t len) {
	if (buf == nullptr || len == 0) {
		return;
	}

	std::string str;
	if (buf[len - 1] == '\n') {
		str.assign(buf, len - 1);
	} else {
		str.assign(buf, len);
	}
	log(level, "{}", str);
}
} // namespace logging
