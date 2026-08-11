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
#else
#	include <linux/types.h>
#endif

/**
 * Identifies the managed runtime whose library was loaded.
 *
 * The BPF program stores one of these values in DvmEvent::libraryType.
 * The same numeric values appear verbatim in the JSON output field
 * "libraryType", so treat them as a stable ABI — do not renumber.
 */
enum DvmLibraryType : __u32 {
	DVM_LIBRARY_TYPE_UNKNOWN = 0,
	DVM_LIBRARY_TYPE_JVM     = 1, /* e.g. libjvm.so  */
	DVM_LIBRARY_TYPE_DOTNET  = 2, /* e.g. libcoreclr.so */
};

/**
 * Kernel-side event emitted by the DVM BPF program when a managed-runtime
 * library is loaded into a process.
 *
 * Passed through a BPF ring buffer to userspace.  Time is expressed as a
 * monotonic nanosecond timestamp (bpf_ktime_get_ns); userspace converts to
 * clock ticks via nsToTicks() before publishing.
 */
struct DvmEvent {
	__u64 loadTimeNs;  /* library load timestamp (monotonic ns from BPF) */
	__u32 pid;         /* PID of the process that performed the load      */
	__u32 libraryType; /* one of DvmLibraryType                           */
};
