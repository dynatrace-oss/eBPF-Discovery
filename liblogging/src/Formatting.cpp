// SPDX-License-Identifier: Apache-2.0

#include "Formatting.h"

namespace logging {

std::string_view trimNewline(std::string_view str) {
	if (!str.empty() && str.back() == '\n') {
		return std::string_view(str.data(), str.length() - 1);
	} else {
		return str;
	}
}

std::string vaFormat(const char* format, va_list args) noexcept {
	std::string result(256, '\0');

	va_list argsCopy;
	va_copy(argsCopy, args);

	int len{std::vsnprintf(result.data(), result.size() + 1, format, args)};

	if (len <= 0) {
		return result;
	}

	if (len <= (int)result.size()) {
		result.resize(len);
		return result;
	}

	result.resize(len);
	len = std::vsnprintf(result.data(), result.size() + 1, format, argsCopy);

	if (len <= 0) {
		return {};
	}

	return result;
}

std::string vaFormat(const char* format, ...) noexcept {
	va_list args;
	va_start(args, format);
	auto result{vaFormat(format, args)};
	va_end(args);
	return result;
}

} // namespace logging
