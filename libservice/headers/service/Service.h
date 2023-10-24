// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>

namespace service {

struct Service {
	uint32_t pid;
	std::string endpoint;
	uint32_t internalClientsNumber{0u};
	uint32_t externalClientsNumber{0u};

	bool operator==(const Service& other) const {
		return pid == other.pid && endpoint == other.endpoint && internalClientsNumber == other.internalClientsNumber &&
			   externalClientsNumber == other.externalClientsNumber;
	}
};

} // namespace service