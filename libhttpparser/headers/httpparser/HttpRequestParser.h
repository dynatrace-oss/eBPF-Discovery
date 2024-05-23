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

#include "ebpfdiscoveryshared/Constants.h"

#include <string>
#include <string_view>
#include <vector>

namespace httpparser {

struct HttpRequest {
	std::string method;
	std::string url;
	std::string protocol;
	std::string host;
	std::vector<std::string> xForwardedFor;

	HttpRequest();
	void clear();
};

class HttpRequestParser {
public:
	HttpRequestParser();

	// Parse passed data while advancing the state machine
	size_t parse(std::string_view data);

	bool isInvalidState() const;
	bool isFinished() const;

	void reset();

	HttpRequest result;

	enum class State {
		METHOD,
		SPACE_BEFORE_URL,
		URL,
		SPACE_BEFORE_PROTOCOL,
		PROTOCOL,
		HEADER_NEWLINE,
		HEADER_KEY,
		SPACE_BEFORE_HEADER_VALUE,
		HEADER_VALUE,
		HEADERS_END,
		FINISHED,
		INVALID,
	};

protected:
	State state;

	void setInvalidState();
	void setFinishedState();

	void handleChar(const char ch);
	void handleCharMethod(const char ch);
	void handleCharSpaceBeforeUrl(const char ch);
	void handleCharUrl(const char ch);
	void handleCharSpaceBeforeProtocol(const char ch);
	void handleCharProtocol(const char ch);
	void handleCharHeaderNewline(const char ch);
	void handleCharHeaderKey(const char ch);
	void handleCharSpaceBeforeHeaderValue(const char ch);
	void handleCharHeaderValue(const char ch);
	void handleCharHeadersEnd(const char ch);

	bool isCurrentHeaderKeyHost();
	bool isCurrentHeaderKeyXForwardedFor();

	void parseXForwardedFor(const std::string& data);

	struct HttpHeader {
		std::string key;
		std::string value;
	};

	HttpHeader currentHeader;
	size_t length;
};

} // namespace httpparser
