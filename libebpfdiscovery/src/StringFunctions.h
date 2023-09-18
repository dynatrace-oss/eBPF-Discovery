// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>

namespace ebpfdiscovery {

// Data in network byte order is expected
std::string ipv4ToString(const uint8_t ip[4]);
std::string ipv6ToString(const uint8_t ip[16]);

} // namespace ebpfdiscovery
