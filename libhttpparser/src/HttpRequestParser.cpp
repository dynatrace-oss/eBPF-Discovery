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

#include "httpparser/HttpRequestParser.h"

#include <boost/algorithm/string.hpp>

#include <optional>

namespace httpparser {

using State = HttpRequestParser::State;

namespace constants {
static constexpr std::string_view HTTP_1_0{"HTTP/1.0"};
static constexpr std::string_view HTTP_1_1{"HTTP/1.1"};

static constexpr std::string_view VALID_URL_SPECIAL_CHARS{"-._~:/?#[]@!$&'()*+,;=%"};
static constexpr std::string_view VALID_HEADER_KEY_SPECIAL_CHARS{"!#$%&'*+-.^_`|~"};
static constexpr std::string_view VALID_HEADER_VALUE_SPECIAL_CHARS{"`~!@#$%^&*()-_=+[]{}\\|;'<>,.?/ "};
static constexpr std::string_view VALID_HOST_HEADER_VALUE_SPECIAL_CHARS{"-.:[]"};
static constexpr std::string_view VALID_IP_FOR_HEADER_VALUE_SPECIAL_CHARS{"-.:[], "};

static constexpr std::string_view GET{"GET"};
static constexpr std::string_view POST{"POST"};

[[maybe_unused]] static constexpr std::string_view HOST{"Host"};
static constexpr std::string_view HOST_LOWER{"host"};

static std::list<std::string_view> HEADER_CLIENT_IP_KEYS {"rproxy_remote_address", "true-client-ip", "x-client-ip", "x-forwarded-for", "x-http-client-ip"};
static constexpr uint MAX_HEADER_KEY_LENGTH = 21;
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

inline static bool isValidIpForHeaderValueChar(const char ch) {
	return std::isalnum(ch) || constants::VALID_IP_FOR_HEADER_VALUE_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

HttpRequest::HttpRequest() {
	method.reserve(4);
	protocol.reserve(8);
	isHttps = false;
}

void HttpRequest::clear() {
	method.clear();
	url.clear();
	protocol.clear();
	host.clear();
	clientIp.clear();
	isHttps = false;
}

HttpRequestParser::HttpRequestParser() : state{State::METHOD}, length{0}, isClientIpRead{false} {
}

size_t HttpRequestParser::parse(std::string_view data, __u8 discoveryFlags) {
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
			result.isHttps = discoveryFlags & DISCOVERY_FLAG_SESSION_SSL_HTTP;
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

	if (isCurrentHeaderKeyClientIp() && result.clientIPKey == currentHeader.key) {
		isClientIpRead = true;
		parseClientIPValue(currentHeader.value);
	}

	currentHeader = {};

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

		if (currentHeader.key.size() < constants::MAX_HEADER_KEY_LENGTH) {
			currentHeader.key.push_back(std::tolower(ch));
		}

		return;
	}

	if (isCurrentHeaderKeyHost() && !result.host.empty()) {
		state = State::INVALID;
		return;
	}

	if (isCurrentHeaderKeyClientIp() && !currentHeader.value.empty()) {
		currentHeader.value.push_back(',');
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
	} else if (isCurrentHeaderKeyClientIp()) {
		if (result.clientIPKey.empty()) {
			result.clientIPKey = currentHeader.key;
		}
		currentHeader.value.push_back(ch);
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

	if (ch != '\r' && isCurrentHeaderKeyClientIp()) {
		if (!isValidIpForHeaderValueChar(ch)) {
			setInvalidState();
			return;
		}

		currentHeader.value.push_back(ch);
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

bool HttpRequestParser::isCurrentHeaderKeyHost() const {
	return currentHeader.key == constants::HOST_LOWER;
}

bool HttpRequestParser::isCurrentHeaderKeyClientIp() const {
	return std::find(constants::HEADER_CLIENT_IP_KEYS.begin(),constants::HEADER_CLIENT_IP_KEYS.end(), currentHeader.key) != constants::HEADER_CLIENT_IP_KEYS.end();
}

void HttpRequestParser::reset() {
	state = State::METHOD;
	currentHeader = {};
	length = 0;
	result.clear();
}

static std::optional<std::string> getTextBetweenSquareBrackets(const std::string& input) {
	const auto firstBracketPos{input.find('[')};
	const auto lastBracketPos{input.rfind(']')};

	if (firstBracketPos == std::string::npos || lastBracketPos == std::string::npos || lastBracketPos < firstBracketPos) {
		return std::nullopt;
	}

	return input.substr(firstBracketPos + 1, lastBracketPos - firstBracketPos - 1);
}

void HttpRequestParser::parseClientIPValue(const std::string& data) {
	std::vector<std::string> addresses;
	boost::split(addresses, data, boost::is_any_of(","), boost::token_compress_on);
	for (auto& address : addresses) {
		boost::trim(address);
		if (address.find('.') != std::string::npos) { // IPv4
			if (const auto semicolonPos{address.rfind(':')}; semicolonPos != std::string::npos) {
				address = boost::trim_copy(address.substr(0, semicolonPos));
			}
		} else { // IPv6
			if (const auto ipv6Address{getTextBetweenSquareBrackets(address)}; boost::starts_with(address, "[") && ipv6Address) {
				address = boost::trim_copy(*ipv6Address);
			}
		}
	}

	std::copy(addresses.begin(), addresses.end(), std::back_inserter(result.clientIp));
}

} // namespace httpparser
