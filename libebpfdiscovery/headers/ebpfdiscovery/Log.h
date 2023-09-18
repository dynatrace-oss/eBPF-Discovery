// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ebpfdiscovery/Session.h"
#include "ebpfdiscoveryshared/Types.h"

#include <iostream>
#include <string>

namespace ebpfdiscovery {

void printSession(const Session& session, const DiscoverySessionMeta& meta);

} // namespace ebpfdiscovery
