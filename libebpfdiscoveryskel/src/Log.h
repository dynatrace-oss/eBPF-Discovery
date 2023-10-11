// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct trace_event_raw_bpf_trace_printk___log {};

#define DEBUG_PRINTLN(fmt, ...)                                                    \
	({                                                                             \
		static char newFmt[] = fmt "\0";                                           \
		if (bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk___log)) { \
			bpf_trace_printk(newFmt, sizeof(newFmt) - 1, ##__VA_ARGS__);           \
		} else {                                                                   \
			newFmt[sizeof(newFmt) - 2] = '\n';                                     \
			bpf_trace_printk(newFmt, sizeof(newFmt), ##__VA_ARGS__);               \
		}                                                                          \
	})
