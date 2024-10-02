/*
 * Copyright 2024 Dynatrace LLC
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

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct DiscoveryConfig);
	__uint(max_entries, 1);
} discoveryConfigMap SEC(".maps");

__attribute__((always_inline)) inline static struct DiscoveryConfig* getDiscoveryConfig() {
	__u32 zero = 0;
	return (struct DiscoveryConfig*)bpf_map_lookup_elem(&discoveryConfigMap, &zero);
}
