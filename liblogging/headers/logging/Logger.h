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

#pragma once

#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
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
public:
	Logger(const Logger&) = delete;
	Logger& operator=(const Logger&) = delete;

	static Logger& getInstance();

	void init(bool logToStdout = true, std::filesystem::path logDir = {});
	void setLevel(enum LogLevel level);

	template <typename... Args>
	void log(enum LogLevel level, const char* fmt, const Args&... args) {
		spdLogger.log(static_cast<spdlog::level::level_enum>(level), fmt, args...);
		spdLogger.flush_on(static_cast<spdlog::level::level_enum>(level));
	}

	void vlogf(enum LogLevel level, const char* format, va_list args);

	template <typename... Args>
	void trace(const char* fmt, const Args&... args) {
		spdLogger.trace(fmt, args...);
		spdLogger.flush_on(spdlog::level::trace);
	}

	template <typename... Args>
	void debug(const char* fmt, const Args&... args) {
		spdLogger.debug(fmt, args...);
		spdLogger.flush_on(spdlog::level::debug);
	}

	template <typename... Args>
	void info(const char* fmt, const Args&... args) {
		spdLogger.info(fmt, args...);
		spdLogger.flush_on(spdlog::level::info);
	}

	template <typename... Args>
	void warn(const char* fmt, const Args&... args) {
		spdLogger.warn(fmt, args...);
		spdLogger.flush_on(spdlog::level::warn);
	}

	template <typename... Args>
	void error(const char* fmt, const Args&... args) {
		spdLogger.error(fmt, args...);
		spdLogger.flush_on(spdlog::level::err);
	}

	template <typename... Args>
	void critical(const char* fmt, const Args&... args) {
		spdLogger.critical(fmt, args...);
		spdLogger.flush_on(spdlog::level::critical);
	}

	template <typename... Args>
	void trace(const char* str) {
		spdLogger.trace(str);
		spdLogger.flush_on(spdlog::level::trace);
	}

	template <typename... Args>
	void debug(const char* str) {
		spdLogger.debug(str);
		spdLogger.flush_on(spdlog::level::debug);
	}

	template <typename... Args>
	void info(const char* str) {
		spdLogger.info(str);
		spdLogger.flush_on(spdlog::level::info);
	}

	template <typename... Args>
	void warn(const char* str) {
		spdLogger.warn(str);
		spdLogger.flush_on(spdlog::level::warn);
	}

	template <typename... Args>
	void error(const char* str) {
		spdLogger.error(str);
		spdLogger.flush_on(spdlog::level::err);
	}

	template <typename... Args>
	void critical(const char* str) {
		spdLogger.critical(str);
		spdLogger.flush_on(spdlog::level::critical);
	}

private:
	static constexpr std::size_t MAX_FILE_SIZE_IN_BYTES{1024 * 1024};
	static constexpr std::size_t MAX_FILES{100};

	Logger();

	void loggerSetDefaults();
	void setLogger(spdlog::logger logger);

	spdlog::logger spdLogger;
};

} // namespace logging

#define LOG_TRACE(...) logging::Logger::getInstance().trace(__VA_ARGS__)
#define LOG_DEBUG(...) logging::Logger::getInstance().debug(__VA_ARGS__)
#define LOG_INFO(...) logging::Logger::getInstance().info(__VA_ARGS__)
#define LOG_WARN(...) logging::Logger::getInstance().warn(__VA_ARGS__)
#define LOG_ERROR(...) logging::Logger::getInstance().error(__VA_ARGS__)
#define LOG_CRITICAL(...) logging::Logger::getInstance().critical(__VA_ARGS__)
