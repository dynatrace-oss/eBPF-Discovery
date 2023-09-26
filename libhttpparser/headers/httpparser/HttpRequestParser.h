// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "ebpfdiscoveryshared/Constants.h"

#include <string>
#include <string_view>

namespace httpparser {

struct HttpRequest {
	std::string method;
	std::string url;
	std::string protocol;
	std::string host;
	std::string xForwardedFor;

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

private:
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

	std::string currentHeaderKey;
	size_t length;
};

} // namespace httpparser
