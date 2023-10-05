// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <istream>
#include <optional>
#include <string>
#include <vector>

namespace logging {

enum LogLevel {
	Trace = static_cast<int>(spdlog::level::trace),
	Debug = static_cast<int>(spdlog::level::debug),
	Info = static_cast<int>(spdlog::level::info),
	Warn = static_cast<int>(spdlog::level::warn),
	Err = static_cast<int>(spdlog::level::err),
	Critical = static_cast<int>(spdlog::level::critical),
	Off = static_cast<int>(spdlog::level::off)
};

std::istream& operator>>(std::istream& in, LogLevel& level);

class Logger {
private:
	static constexpr std::size_t max_size = 102400;
	static constexpr std::size_t max_files = 3;

public:
	Logger();
	~Logger() = default;
	Logger(const Logger&) = delete;
	Logger& operator=(const Logger&) = delete;

	void setLevel(enum LogLevel level);
	void setup(std::string name = {}, bool logToStdout = true, const std::string_view& logDir = {});

	template <typename... Args>
	void log(enum LogLevel level, const char* fmt, const Args&... args) {
		spdLogger.log(static_cast<spdlog::level::level_enum>(level), fmt, args...);
	}

	void vlogf(enum LogLevel level, const char* format, va_list args);

	template <typename... Args>
	void trace(const char* fmt, const Args&... args) {
		spdLogger.trace(fmt, args...);
	}

	template <typename... Args>
	void debug(const char* fmt, const Args&... args) {
		spdLogger.debug(fmt, args...);
	}

	template <typename... Args>
	void info(const char* fmt, const Args&... args) {
		spdLogger.info(fmt, args...);
	}

	template <typename... Args>
	void warn(const char* fmt, const Args&... args) {
		spdLogger.warn(fmt, args...);
	}

	template <typename... Args>
	void error(const char* fmt, const Args&... args) {
		spdLogger.error(fmt, args...);
	}

	template <typename... Args>
	void critical(const char* fmt, const Args&... args) {
		spdLogger.critical(fmt, args...);
	}

	template <typename... Args>
	void trace(const char* str) {
		spdLogger.trace(str);
	}

	template <typename... Args>
	void debug(const char* str) {
		spdLogger.debug(str);
	}

	template <typename... Args>
	void info(const char* str) {
		spdLogger.info(str);
	}

	template <typename... Args>
	void warn(const char* str) {
		spdLogger.warn(str);
	}

	template <typename... Args>
	void error(const char* str) {
		spdLogger.error(str);
	}

	template <typename... Args>
	void critical(const char* str) {
		spdLogger.critical(str);
	}

private:
	void loggerSetDefaults();
	void setLogger(spdlog::logger logger);
	void logLine(enum LogLevel level, const char* str, size_t len);

	spdlog::logger spdLogger;
};

} // namespace logging
