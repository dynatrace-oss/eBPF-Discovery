// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define DEBUG_PRINT(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
