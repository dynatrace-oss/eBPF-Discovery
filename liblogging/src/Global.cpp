// SPDX-License-Identifier: Apache-2.0
#include "logging/Global.h"

namespace logging {

Logger& Global::getInstance() {
	static Logger instance;
	return instance;
}

} // namespace logging
