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

#include "Formatting.h"

namespace logging {

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
