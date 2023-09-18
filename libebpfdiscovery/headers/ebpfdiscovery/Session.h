// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ebpfdiscoveryshared/Types.h"
#include "httpparser/HttpRequestParser.h"

namespace ebpfdiscovery {

using httpparser::HttpRequestParser;

struct Session {
	HttpRequestParser parser;

	void reset();
};

} // namespace ebpfdiscovery
