// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "logging/Logger.h"

namespace logging {

class Global {
public:
	static Logger& getInstance();

private:
	Global() = default;
};

#define LOG_TRACE(...) logging::Global::getInstance().trace(__VA_ARGS__)
#define LOG_DEBUG(...) logging::Global::getInstance().debug(__VA_ARGS__)
#define LOG_INFO(...) logging::Global::getInstance().info(__VA_ARGS__)
#define LOG_WARN(...) logging::Global::getInstance().warn(__VA_ARGS__)
#define LOG_ERROR(...) logging::Global::getInstance().error(__VA_ARGS__)
#define LOG_CRITICAL(...) logging::Global::getInstance().critical(__VA_ARGS__)

} // namespace logging
