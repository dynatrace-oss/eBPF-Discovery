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

#include <cstdint>
#include <string>

namespace service {

struct Service {
	uint32_t pid;
	std::string endpoint;
	std::string domain;
	std::string scheme;
	uint32_t internalClientsNumber{0u};
	uint32_t externalClientsNumber{0u};

	bool operator==(const Service& other) const {
		return pid == other.pid && endpoint == other.endpoint && domain == other.domain && scheme == other.scheme && internalClientsNumber == other.internalClientsNumber &&
			   externalClientsNumber == other.externalClientsNumber;
	}
};

} // namespace service