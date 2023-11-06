// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <string>

namespace service {

using IPv4bytes = uint8_t[4];
using IPv6bytes = uint8_t[16];

std::string ipv4ToString(const IPv4bytes addr);
std::string ipv6ToString(const IPv6bytes addr);

} // namespace service
