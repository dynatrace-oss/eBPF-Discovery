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
	std::string x_forwarded_for;

	HttpRequest();
	void clear();
};

class HttpRequestParser {
public:
	HttpRequestParser();

	// Parse passed data while advancing the state machine
	size_t parse(std::string_view data);

	bool is_invalid_state() const;
	bool is_finished() const;

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

	void set_invalid_state();
	void set_finished_state();

	void handle_char(const char ch);
	void handle_char_method(const char ch);
	void handle_char_space_before_url(const char ch);
	void handle_char_url(const char ch);
	void handle_char_space_before_protocol(const char ch);
	void handle_char_protocol(const char ch);
	void handle_char_header_newline(const char ch);
	void handle_char_header_key(const char ch);
	void handle_char_space_before_header_value(const char ch);
	void handle_char_header_value(const char ch);
	void handle_char_headers_end(const char ch);

	bool is_current_header_key_host();
	bool is_current_header_key_x_forwarded_for();

	std::string currentHeaderKey;
	size_t _length;
};

} // namespace httpparser
