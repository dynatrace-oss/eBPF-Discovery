// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "vmlinux.h"

#include "bpf/bpf_helpers.h"

__u32 pidTgidToPid(__u64 pidTgid) {
	return pidTgid >> 32;
}
