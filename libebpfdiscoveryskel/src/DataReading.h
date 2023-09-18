// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

__attribute__((always_inline)) inline static int dataReadingStreq(const char* src, const char* str, size_t len) {
	char ch;
	for (int i = 0; i < len; ++i) {
		bpf_probe_read(&ch, sizeof(char), (char*)src + i);
		if (ch != str[i]) {
			return i + 1;
		}
	}
	return 0;
}
