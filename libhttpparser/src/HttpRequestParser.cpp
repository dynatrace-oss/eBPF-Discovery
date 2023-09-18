// SPDX-License-Identifier: Apache-2.0

#include "httpparser/HttpRequestParser.h"

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

inline static bool is_valid_url_char(const char ch) {
	return std::isalnum(ch) || constants::VALID_URL_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

inline static bool is_valid_header_key_char(const char ch) {
	return std::isalnum(ch) || constants::VALID_HEADER_KEY_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

inline static bool is_valid_header_value_char(const char ch) {
	return std::isalnum(ch) || constants::VALID_HEADER_VALUE_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

inline static bool is_valid_host_header_value_char(const char ch) {
	return std::isalnum(ch) || constants::VALID_HOST_HEADER_VALUE_SPECIAL_CHARS.find(ch) != std::string_view::npos;
}

inline static bool is_valid_x_forwarded_for_header_value_char(const char ch) {
	return std::isalnum(ch) || constants::VALID_X_FORWARDED_FOR_HEADER_VALUE_SPECIAL_CHARS.find(ch) != std::string_view::npos;
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
	x_forwarded_for.clear();
}

HttpRequestParser::HttpRequestParser() : state{State::METHOD}, _length{0} {
}

size_t HttpRequestParser::parse(std::string_view data) {
	size_t i{0};
	while (i < data.size()) {
		if (_length > MAX_HTTP_REQUEST_LENGTH) {
			set_invalid_state();
			return i;
		}

		handle_char(data[i]);

		i++;
		_length++;

		if (state == State::FINISHED || state == State::INVALID) {
			return i;
		}
	}

	// We're in the middle of a possibly valid HTTP request. We're expecting more data chunk(s).
	return i;
}

bool HttpRequestParser::is_invalid_state() const {
	return state == State::INVALID;
}

bool HttpRequestParser::is_finished() const {
	return state == State::FINISHED || state == State::INVALID;
}

void HttpRequestParser::set_invalid_state() {
	state = State::INVALID;
}

void HttpRequestParser::set_finished_state() {
	state = State::FINISHED;
}

void HttpRequestParser::handle_char(const char ch) {
	switch (state) {
	case State::METHOD:
		handle_char_method(ch);
		break;
	case State::SPACE_BEFORE_URL:
		handle_char_space_before_url(ch);
		break;
	case State::URL:
		handle_char_url(ch);
		break;
	case State::SPACE_BEFORE_PROTOCOL:
		handle_char_space_before_protocol(ch);
		break;
	case State::PROTOCOL:
		handle_char_protocol(ch);
		break;
	case State::HEADER_NEWLINE:
		handle_char_header_newline(ch);
		break;
	case State::HEADER_KEY:
		handle_char_header_key(ch);
		break;
	case State::SPACE_BEFORE_HEADER_VALUE:
		handle_char_space_before_header_value(ch);
		break;
	case State::HEADER_VALUE:
		handle_char_header_value(ch);
		break;
	case State::HEADERS_END:
		handle_char_headers_end(ch);
		break;
	case State::FINISHED:
	case State::INVALID:
		break;
	}
}

void HttpRequestParser::handle_char_method(const char ch) {
	if (std::isupper(ch)) {
		result.method.push_back(ch);

		// We expect only GET and POST requests
		bool isMaybeGet{constants::GET.substr(0, result.method.length()) == result.method};
		bool isMaybePost{constants::POST.substr(0, result.method.length()) == result.method};

		if (!isMaybeGet && !isMaybePost) {
			set_invalid_state();
			return;
		}
		return;
	}

	if (ch != ' ') {
		set_invalid_state();
		return;
	}

	if (result.method != constants::GET && result.method != constants::POST) {
		set_invalid_state();
		return;
	}

	state = State::SPACE_BEFORE_URL;
}

void HttpRequestParser::handle_char_space_before_url(const char ch) {
	if (ch != '/') {
		// We expect every HTTP request URI to start with /
		set_invalid_state();
		return;
	}

	result.url.push_back(ch);
	state = State::URL;
}

void HttpRequestParser::handle_char_url(const char ch) {
	if (ch != ' ') {
		if (!is_valid_url_char(ch)) {
			set_invalid_state();
			return;
		}

		result.url.push_back(ch);
		return;
	}

	state = State::SPACE_BEFORE_PROTOCOL;
}

void HttpRequestParser::handle_char_space_before_protocol(const char ch) {
	if (ch != 'H') {
		// First letter of HTTP/x.x
		set_invalid_state();
		return;
	}

	result.protocol.push_back(ch);
	state = State::PROTOCOL;
}

void HttpRequestParser::handle_char_protocol(const char ch) {
	if (ch != '\r') {
		result.protocol.push_back(ch);

		bool isMaybe1_0{constants::HTTP_1_0.substr(0, result.protocol.length()) == result.protocol};
		bool isMaybe1_1{constants::HTTP_1_1.substr(0, result.protocol.length()) == result.protocol};

		if (!isMaybe1_0 && !isMaybe1_1) {
			set_invalid_state();
			return;
		}
		return;
	}

	if (result.protocol != constants::HTTP_1_0 && result.protocol != constants::HTTP_1_1) {
		set_invalid_state();
		return;
	}

	state = State::HEADER_NEWLINE;
}

void HttpRequestParser::handle_char_header_newline(const char ch) {
	if (ch != '\n') {
		set_invalid_state();
		return;
	}

	currentHeaderKey.clear();
	state = State::HEADER_KEY;
}

void HttpRequestParser::handle_char_header_key(const char ch) {
	if (ch == '\r') {
		state = State::HEADERS_END;
		return;
	}

	if (ch == ' ') {
		return;
	}

	if (ch != ':') {
		if (!is_valid_header_key_char(ch)) {
			set_invalid_state();
			return;
		}

		if (currentHeaderKey.size() < constants::X_FORWARDED_FOR.size()) {
			currentHeaderKey.push_back(std::tolower(ch));
		}

		return;
	}

	if (is_current_header_key_host() && !result.host.empty()) {
		state = State::INVALID;
		return;
	}

	if (is_current_header_key_x_forwarded_for() && !result.x_forwarded_for.empty()) {
		result.x_forwarded_for.push_back(',');
	}

	state = State::SPACE_BEFORE_HEADER_VALUE;
}

void HttpRequestParser::handle_char_space_before_header_value(const char ch) {
	if (ch == ' ') {
		return;
	}

	if (!is_valid_header_value_char(ch)) {
		set_invalid_state();
		return;
	}

	if (is_current_header_key_host()) {
		result.host.push_back(ch);
	} else if (is_current_header_key_x_forwarded_for()) {
		result.x_forwarded_for.push_back(ch);
	}

	state = State::HEADER_VALUE;
}

void HttpRequestParser::handle_char_header_value(const char ch) {
	if (ch != '\r' && is_current_header_key_host()) {
		if (!is_valid_host_header_value_char(ch)) {
			set_invalid_state();
			return;
		}

		result.host.push_back(ch);
		return;
	}

	if (ch != '\r' && is_current_header_key_x_forwarded_for()) {
		if (!is_valid_x_forwarded_for_header_value_char(ch)) {
			set_invalid_state();
			return;
		}

		result.x_forwarded_for.push_back(ch);
		return;
	}

	if (ch != '\r' && !is_valid_header_value_char(ch)) {
		set_invalid_state();
		return;
	}

	if (ch != '\r') {
		return;
	}

	state = State::HEADER_NEWLINE;
}

void HttpRequestParser::handle_char_headers_end(const char ch) {
	if (ch != '\n') {
		set_invalid_state();
		return;
	}

	// At this stage there may be additional POST data. It's fine to ignore it.
	// We also don't handle pipelined HTTP requests as they are uncommon.
	set_finished_state();
	return;
}

inline bool HttpRequestParser::is_current_header_key_host() {
	return currentHeaderKey == constants::HOST_LOWER;
}

inline bool HttpRequestParser::is_current_header_key_x_forwarded_for() {
	return currentHeaderKey == constants::X_FORWARDED_FOR_LOWER;
}

void HttpRequestParser::reset() {
	state = State::METHOD;
	currentHeaderKey.clear();
	_length = 0;
	result.clear();
}

} // namespace httpparser
