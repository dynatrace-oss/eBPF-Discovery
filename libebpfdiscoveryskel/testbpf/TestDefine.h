// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "DiscoveryTestConstants.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u32 runnerPid = 0;

char* inPtr = NULL;
size_t inLen = 0;
int outRet = 0;

#define TEST_ENTRY SEC("fentry/do_nanosleep")
#define CHECK_TEST_RUNNER(runnerPid)                       \
	if ((bpf_get_current_pid_tgid() >> 32) != runnerPid) { \
		return 0;                                          \
	}
