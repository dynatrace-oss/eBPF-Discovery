/*
* Copyright 2026 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#ifdef __TARGET_BPF
#	include "vmlinux.h"
#define COMM_SIZE TASK_COMM_LEN
#else
#	include <linux/types.h>
#define COMM_SIZE 16
#endif

struct SlpEvent{
	__u64 cpuTimeNs;
	__u64 startTimeNs;
	__u32 pid;
	__u32 parentPid;
	char comm[COMM_SIZE];
};

struct SlpThreadsData{
	__s64 count;
	__u64 cpuTime;
};
