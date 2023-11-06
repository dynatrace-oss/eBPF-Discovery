// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdarg>
#include <string>

namespace logging {

std::string vaFormat(const char* format, va_list args) noexcept;
std::string vaFormat(const char* format, ...) noexcept;

} // namespace logging
