// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct DiscoveryConfig);
	__uint(max_entries, 1);
} discoveryConfigMap SEC(".maps");

__attribute__((always_inline)) inline static struct DiscoveryConfig* getDiscoveryConfig() {
	static __u32 zero = 0;
	return (struct DiscoveryConfig*)bpf_map_lookup_elem(&discoveryConfigMap, &zero);
}
