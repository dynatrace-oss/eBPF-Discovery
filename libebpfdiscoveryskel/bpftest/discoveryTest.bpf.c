// SPDX-License-Identifier: GPL-2.0
#include "DataFunctions.h"

#include "discoveryTest.h"
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u32 runnerPid = 0;

char* inPtr = NULL;
size_t inLen = 0;
int outRet = 0;

SEC("fentry/do_nanosleep") int BPF_PROG(testDataProbeIsBeginningOfHttpRequest) {
	if ((bpf_get_current_pid_tgid() >> 32) != runnerPid) {
		return 0;
	}

	if (inPtr != NULL && inLen < DISCOVERY_TEST_MAX_INPUT_LEN) {
		outRet = dataProbeIsBeginningOfHttpRequest(inPtr, inLen);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
