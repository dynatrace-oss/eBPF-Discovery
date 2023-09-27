// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "ebpfdiscoveryshared/Constants.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

__attribute__((always_inline)) inline static int dataProbeEqualToString(const char* src, const char* str, size_t len) {
	char ch;
	for (size_t i = 0; i < len; ++i) {
		int res = bpf_probe_read(&ch, sizeof(char), (char*)src + i);
		if (res < 0) {
			return res;
		}

		if (ch != str[i] || ch == '\0') {
			return i + 1;
		}
	}
	return len;
}

__attribute__((always_inline)) inline static bool dataProbeIsBeginningOfHttpRequest(const char* ptr, size_t len) {
	// We expect only GET and POST requests. We expect request URI's to start with a slash as absolute urls are mainly used in
	// requests to proxy servers.
	return len >= DISCOVERY_MIN_HTTP_REQUEST_LENGTH &&
		   (dataProbeEqualToString(ptr, "GET /", 5) == 5 || dataProbeEqualToString(ptr, "POST /", 6) == 6);
}
