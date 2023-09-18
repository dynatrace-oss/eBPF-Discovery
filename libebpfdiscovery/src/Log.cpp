// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/Log.h"

#include "StringFunctions.h"

#include <algorithm>

namespace ebpfdiscovery {

void printSession(const Session& session, const DiscoverySessionMeta& meta) {
	const auto& request{session.parser.result};
	std::cout << request.method << " " << request.host << request.url;

	if (const auto& x_forwarded_for{request.x_forwarded_for}; !x_forwarded_for.empty()) {
		std::cout << " X-Forwarded-For: " << '"' << x_forwarded_for << '"';
	} else if (discoverySessionFlagsIsIPv4(meta.flags)) {
		if (auto src_ipv4{ipv4ToString(meta.sourceIPData)}; !src_ipv4.empty())
			std::cout << " src_ipv4: " << '"' << src_ipv4 << '"';
	} else if (discoverySessionFlagsIsIPv6(meta.flags)) {
		if (auto src_ipv6{ipv6ToString(meta.sourceIPData)}; !src_ipv6.empty())
			std::cout << " src_ipv6: " << '"' << src_ipv6 << '"';
	}

	std::cout << '\n';
}

} // namespace ebpfdiscovery
