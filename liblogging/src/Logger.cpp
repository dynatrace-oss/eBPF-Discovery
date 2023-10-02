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

Logger::Logger() : spdLogger("default") {
	loggerSetDefaults();
}

void Logger::setLevel(enum LogLevel level) {
	spdLogger.set_level(static_cast<spdlog::level::level_enum>(level));
}

void Logger::setup(std::string name, bool logToStdout, const std::string& logDir) {
	namespace fs = std::filesystem;

	if (name.empty()) {
		name = "default";
	}

	std::vector<spdlog::sink_ptr> sinks;
	if (logToStdout) {
		sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
	}

	if (!logDir.empty() && !fs::is_directory(logDir)) {
		setLogger(spdlog::logger(name, sinks.begin(), sinks.end()));
		error("{} doesn't exist or is not a directory.", logDir);
		return;
	}

	if (!logDir.empty()) {
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

	int resultSize = vsnprintf(staticBuf, staticBufSize, format, args);
	if (resultSize <= staticBufSize) {
		logLine(level, staticBuf, resultSize);
		return;
	}

	static va_list args2;
	va_copy(args2, args);

	char buf[resultSize]{};
	vsnprintf(buf, resultSize, format, args2);

	logLine(level, buf, resultSize);
}

void Logger::setLogger(spdlog::logger logger) {
	spdLogger = std::move(logger);
	loggerSetDefaults();
}

void Logger::loggerSetDefaults() {
	spdLogger.set_level(spdlog::level::info);
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
