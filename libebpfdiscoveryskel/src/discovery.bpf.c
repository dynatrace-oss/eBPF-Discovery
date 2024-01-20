// SPDX-License-Identifier: GPL-2.0

#include "LibSSLProbes.h"
#include "Log.h"
#include "SyscallProbes.h"

// vmlinux.h is required by bpf_helpers.h
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";
