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

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct trace_event_raw_bpf_trace_printk___log {};

#ifdef DEBUG
#	define DEBUG_PRINTLN(fmt, ...)                                                    \
		({                                                                             \
			static char newFmt[] = "[ebpf-discovery] " fmt "\0";                       \
			if (bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk___log)) { \
				bpf_trace_printk(newFmt, sizeof(newFmt) - 1, ##__VA_ARGS__);           \
			} else {                                                                   \
				newFmt[sizeof(newFmt) - 2] = '\n';                                     \
				bpf_trace_printk(newFmt, sizeof(newFmt), ##__VA_ARGS__);               \
			}                                                                          \
		})
#else
#	define DEBUG_PRINTLN(fmt, ...)
#endif
