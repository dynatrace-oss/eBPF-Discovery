// SPDX-License-Identifier: Apache-2.0

#include "httpparser/HttpRequestParser.h"
#include <iostream>

namespace httpparser {

using State = HttpRequestParser::State;

namespace constants {
static constexpr std::string_view HTTP_1_0{"HTTP/1.0"};
static constexpr std::string_view HTTP_1_1{"HTTP/1.1"};

static constexpr std::string_view VALID_URL_SPECIAL_CHARS{"-._~:/?#[]@!$&'()*+,;=%"};
static constexpr std::string_view VALID_HEADER_KEY_SPECIAL_CHARS{"!#$%&'*+-.^_`|~"};
static constexpr std::string_view VALID_HEADER_VALUE_SPECIAL_CHARS{"`~!@#$%^&*()-_=+[]{}\\|;'<>,.?/ "};
static constexpr std::string_view VALID_HOST_HEADER_VALUE_SPECIAL_CHARS{"-.:[]"};
static constexpr std::string_view VALID_X_FORWARDED_FOR_HEADER_VALUE_SPECIAL_CHARS{"-.:[], "};

static constexpr std::string_view GET{"GET"};
static constexpr std::string_view POST{"POST"};

static constexpr std::string_view HOST{"Host"};
static constexpr std::string_view HOST_LOWER{"host"};

static constexpr std::string_view X_FORWARDED_FOR{"X-Forwarded-For"};
static constexpr std::string_view X_FORWARDED_FOR_LOWER{"x-forwarded-for"};
} // namespace constants

inline static bool isValidUrlChar(const char ch) {
	return std::isalnum(ch) || constants::VALID_URL_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

inline static bool isValidHeaderKeyChar(const char ch) {
	return std::isalnum(ch) || constants::VALID_HEADER_KEY_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

inline static bool isValidHeaderValueChar(const char ch) {
	return std::isalnum(ch) || constants::VALID_HEADER_VALUE_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

inline static bool isValidHostHeaderValueChar(const char ch) {
	return std::isalnum(ch) || constants::VALID_HOST_HEADER_VALUE_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

inline static bool isValidXForwardedForHeaderValueChar(const char ch) {
	return std::isalnum(ch) || constants::VALID_X_FORWARDED_FOR_HEADER_VALUE_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

void XForwardedFor::clear() {
	addresses.clear();
}

void XForwardedForValueParser::parse(std::string_view data) {
	auto beg{0};
	while (beg < data.length()) {
		auto end{data.find_first_of(',', beg)};
		auto const field{data.substr(beg, end - beg)};
		result.addresses.push_back(std::string(field));
		if (end == std::string_view::npos) {
			return;
		}
		beg = end + 1;
	}
	return;
}

HttpRequest::HttpRequest() {
	method.reserve(4);
	protocol.reserve(8);
}

void HttpRequest::clear() {
	method.clear();
	url.clear();
	protocol.clear();
	host.clear();
	xForwardedFor.clear();
}

HttpRequestParser::HttpRequestParser() : state{State::METHOD}, length{0} {
}

size_t HttpRequestParser::parse(std::string_view data) {
	size_t i{0};
	while (i < data.size()) {
		if (length > DISCOVERY_MAX_HTTP_REQUEST_LENGTH) {
			setInvalidState();
			return i;
		}

		handleChar(data[i]);

		i++;
		length++;

		if (state == State::FINISHED || state == State::INVALID) {
			return i;
		}
	}

	// We're in the middle of a possibly valid HTTP request. We're expecting more data chunk(s).
	return i;
}

bool HttpRequestParser::isInvalidState() const {
	return state == State::INVALID;
}

bool HttpRequestParser::isFinished() const {
	return state == State::FINISHED || state == State::INVALID;
}

void HttpRequestParser::setInvalidState() {
	state = State::INVALID;
}

void HttpRequestParser::setFinishedState() {
	state = State::FINISHED;
}

void HttpRequestParser::handleChar(const char ch) {
	switch (state) {
	case State::METHOD:
		handleCharMethod(ch);
		break;
	case State::SPACE_BEFORE_URL:
		handleCharSpaceBeforeUrl(ch);
		break;
	case State::URL:
		handleCharUrl(ch);
		break;
	case State::SPACE_BEFORE_PROTOCOL:
		handleCharSpaceBeforeProtocol(ch);
		break;
	case State::PROTOCOL:
		handleCharProtocol(ch);
		break;
	case State::HEADER_NEWLINE:
		handleCharHeaderNewline(ch);
		break;
	case State::HEADER_KEY:
		handleCharHeaderKey(ch);
		break;
	case State::SPACE_BEFORE_HEADER_VALUE:
		handleCharSpaceBeforeHeaderValue(ch);
		break;
	case State::HEADER_VALUE:
		handleCharHeaderValue(ch);
		break;
	case State::HEADERS_END:
		handleCharHeadersEnd(ch);
		break;
	case State::FINISHED:
	case State::INVALID:
		break;
	}
}

void HttpRequestParser::handleCharMethod(const char ch) {
	if (std::isupper(ch)) {
		result.method.push_back(ch);

		// We expect only GET and POST requests
		bool isMaybeGet{constants::GET.substr(0, result.method.length()) == result.method};
		bool isMaybePost{constants::POST.substr(0, result.method.length()) == result.method};

		if (!isMaybeGet && !isMaybePost) {
			setInvalidState();
			return;
		}
		return;
	}

	if (ch != ' ') {
		setInvalidState();
		return;
	}

	if (result.method != constants::GET && result.method != constants::POST) {
		setInvalidState();
		return;
	}

	state = State::SPACE_BEFORE_URL;
}

void HttpRequestParser::handleCharSpaceBeforeUrl(const char ch) {
	if (ch != '/') {
		// We expect every HTTP request URI to start with /
		setInvalidState();
		return;
	}

	result.url.push_back(ch);
	state = State::URL;
}

void HttpRequestParser::handleCharUrl(const char ch) {
	if (ch != ' ') {
		if (!isValidUrlChar(ch)) {
			setInvalidState();
			return;
		}

		result.url.push_back(ch);
		return;
	}

	state = State::SPACE_BEFORE_PROTOCOL;
}

void HttpRequestParser::handleCharSpaceBeforeProtocol(const char ch) {
	if (ch != 'H') {
		// First letter of HTTP/x.x
		setInvalidState();
		return;
	}

	result.protocol.push_back(ch);
	state = State::PROTOCOL;
}

void HttpRequestParser::handleCharProtocol(const char ch) {
	if (ch != '\r') {
		result.protocol.push_back(ch);

		bool isMaybe1_0{constants::HTTP_1_0.substr(0, result.protocol.length()) == result.protocol};
		bool isMaybe1_1{constants::HTTP_1_1.substr(0, result.protocol.length()) == result.protocol};

		if (!isMaybe1_0 && !isMaybe1_1) {
			setInvalidState();
			return;
		}
		return;
	}

	if (result.protocol != constants::HTTP_1_0 && result.protocol != constants::HTTP_1_1) {
		setInvalidState();
		return;
	}

	state = State::HEADER_NEWLINE;
}

void HttpRequestParser::handleCharHeaderNewline(const char ch) {
	if (ch != '\n') {
		setInvalidState();
		return;
	}

	currentHeaderKey.clear();
	state = State::HEADER_KEY;
}

void HttpRequestParser::handleCharHeaderKey(const char ch) {
	if (ch == '\r') {
		state = State::HEADERS_END;
		return;
	}

	if (ch == ' ') {
		return;
	}

	if (ch != ':') {
		if (!isValidHeaderKeyChar(ch)) {
			setInvalidState();
			return;
		}

		if (currentHeaderKey.size() < constants::X_FORWARDED_FOR.size()) {
			currentHeaderKey.push_back(std::tolower(ch));
		}

		return;
	}

	if (isCurrentHeaderKeyHost() && !result.host.empty()) {
		state = State::INVALID;
		return;
	}

	if (isCurrentHeaderKeyXForwardedFor() && !result.xForwardedFor.empty()) {
		result.xForwardedFor.push_back(',');
	}

	state = State::SPACE_BEFORE_HEADER_VALUE;
}

void HttpRequestParser::handleCharSpaceBeforeHeaderValue(const char ch) {
	if (ch == ' ') {
		return;
	}

	if (!isValidHeaderValueChar(ch)) {
		setInvalidState();
		return;
	}

	if (isCurrentHeaderKeyHost()) {
		result.host.push_back(ch);
	} else if (isCurrentHeaderKeyXForwardedFor()) {
		result.xForwardedFor.push_back(ch);
	}

	state = State::HEADER_VALUE;
}

void HttpRequestParser::handleCharHeaderValue(const char ch) {
	if (ch != '\r' && isCurrentHeaderKeyHost()) {
		if (!isValidHostHeaderValueChar(ch)) {
			setInvalidState();
			return;
		}

		result.host.push_back(ch);
		return;
	}

	if (ch != '\r' && isCurrentHeaderKeyXForwardedFor()) {
		if (!isValidXForwardedForHeaderValueChar(ch)) {
			setInvalidState();
			return;
		}

		result.xForwardedFor.push_back(ch);
		return;
	}

	if (ch != '\r' && !isValidHeaderValueChar(ch)) {
		setInvalidState();
		return;
	}

	if (ch != '\r') {
		return;
	}

	state = State::HEADER_NEWLINE;
}

void HttpRequestParser::handleCharHeadersEnd(const char ch) {
	if (ch != '\n') {
		setInvalidState();
		return;
	}

	// At this stage there may be additional POST data. It's fine to ignore it.
	// We also don't handle pipelined HTTP requests as they are uncommon.
	setFinishedState();
	return;
}

inline bool HttpRequestParser::isCurrentHeaderKeyHost() {
	return currentHeaderKey == constants::HOST_LOWER;
}

inline bool HttpRequestParser::isCurrentHeaderKeyXForwardedFor() {
	return currentHeaderKey == constants::X_FORWARDED_FOR_LOWER;
}

void HttpRequestParser::reset() {
	state = State::METHOD;
	currentHeaderKey.clear();
	length = 0;
	result.clear();
}

} // namespace httpparser
