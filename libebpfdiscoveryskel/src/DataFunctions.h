/*
 * Copyright 2023 Dynatrace LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

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

__attribute__((always_inline)) inline static int dataCopyString(const char* src, char* dest, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		if (src[i] == '\0') {
			return i + 1;
		}
		dest[i] = src[i];
	}
	return len;
}
