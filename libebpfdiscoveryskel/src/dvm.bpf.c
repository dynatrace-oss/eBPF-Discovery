/*
 * Copyright 2026 Dynatrace LLC
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

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ebpfdiscoveryshared/DvmTypes.h"
#include "DebugPrint.h"

char LICENSE[] SEC("license") = "GPL";

#define DVM_FILENAME_MAX_LEN 48

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 4096);
} dvmEvents SEC(".maps");

enum DvmLibraryId : __u32 {
	DVM_LIB_UNKNOWN                   = 0,
	/* JVM */
	DVM_LIB_LIBJVM_SO                 = 1,
	DVM_LIB_LIBJAVA_SO                = 2,
	DVM_LIB_LIBVERIFY_SO              = 3,
	DVM_LIB_LIBJLI_SO                 = 4,
	DVM_LIB_LIBZIP_SO                 = 5,
	/* .NET */
	DVM_LIB_CORECLR_DLL               = 6,
	DVM_LIB_CORECLR_NI_DLL            = 7,
	DVM_LIB_LIBCORECLR_SO             = 8,
	DVM_LIB_LIBCLRJIT_SO              = 9,
	DVM_LIB_LIBSYSTEM_NATIVE_SO       = 10,
	DVM_LIB_LIBSYSTEM_IO_PORTS_SO     = 11,
	DVM_LIB_LIBSYSTEM_NET_SECURITY_SO = 12,
};

/*
 * pid -> u16 bitmask of seen DvmLibraryId values (bit N = library N was seen).
 * LRU_HASH evicts the least-recently-used pid automatically, so the map stays
 * bounded without a separate process-exit cleanup hook.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u16);
} dvmSeenMap SEC(".maps");

static __always_inline __u32 classifyFilename(const char name[DVM_FILENAME_MAX_LEN], int len) {
	// JVM libs
	if (len == 9  && __builtin_memcmp(name, "libjvm.so",    9)  == 0) return DVM_LIB_LIBJVM_SO;
	if (len == 9  && __builtin_memcmp(name, "libjli.so",    9)  == 0) return DVM_LIB_LIBJLI_SO;
	if (len == 9  && __builtin_memcmp(name, "libzip.so",    9)  == 0) return DVM_LIB_LIBZIP_SO;
	if (len == 10 && __builtin_memcmp(name, "libjava.so",   10) == 0) return DVM_LIB_LIBJAVA_SO;
	if (len == 12 && __builtin_memcmp(name, "libverify.so", 12) == 0) return DVM_LIB_LIBVERIFY_SO;
	// .NET libs
	if (len == 12 && __builtin_memcmp(name, "libclrjit.so",                    12) == 0) return DVM_LIB_LIBCLRJIT_SO;
	if (len == 13 && __builtin_memcmp(name, "libcoreclr.so",                   13) == 0) return DVM_LIB_LIBCORECLR_SO;
	if (len == 19 && __builtin_memcmp(name, "libSystem.Native.so",              19) == 0) return DVM_LIB_LIBSYSTEM_NATIVE_SO;
	if (len == 26 && __builtin_memcmp(name, "System.Private.CoreLib.dll",       26) == 0) return DVM_LIB_CORECLR_DLL;
	if (len == 28 && __builtin_memcmp(name, "libSystem.IO.Ports.Native.so",     28) == 0) return DVM_LIB_LIBSYSTEM_IO_PORTS_SO;
	if (len == 29 && __builtin_memcmp(name, "System.Private.CoreLib.ni.dll",    29) == 0) return DVM_LIB_CORECLR_NI_DLL;
	if (len == 32 && __builtin_memcmp(name, "libSystem.Net.Security.Native.so", 32) == 0) return DVM_LIB_LIBSYSTEM_NET_SECURITY_SO;
	return DVM_LIB_UNKNOWN;
}

static __always_inline __u32 libraryType(__u32 libId) {
	if (libId == DVM_LIB_LIBJVM_SO    ||
	    libId == DVM_LIB_LIBJAVA_SO   ||
	    libId == DVM_LIB_LIBVERIFY_SO ||
	    libId == DVM_LIB_LIBJLI_SO    ||
	    libId == DVM_LIB_LIBZIP_SO) {
		return DVM_LIBRARY_TYPE_JVM;
	}
	return DVM_LIBRARY_TYPE_DOTNET;
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(dvmVfsOpenHook, const struct path* path, struct file* file) {
	if (!path) {
		return 0;
	}

	char filename[DVM_FILENAME_MAX_LEN] = {};
	const unsigned char* namePtr = BPF_CORE_READ(path, dentry, d_name.name);
	int nameLen = bpf_probe_read_kernel_str(filename, sizeof(filename), namePtr);
	if (nameLen <= 1) {
		return 0;
	}

	__u32 libId = classifyFilename(filename, nameLen - 1);
	if (libId == DVM_LIB_UNKNOWN) {
		return 0;
	}

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u16 bit = (__u16)(1u << libId);

	__u16* seenMask = bpf_map_lookup_elem(&dvmSeenMap, &pid);
	if (seenMask && (*seenMask & bit)) {
		return 0;
	}

	__u16 newMask = seenMask ? (*seenMask | bit) : bit;
	bpf_map_update_elem(&dvmSeenMap, &pid, &newMask, BPF_ANY);

	struct DvmEvent* event = bpf_ringbuf_reserve(&dvmEvents, sizeof(struct DvmEvent), 0);
	if (!event) {
		DEBUG_PRINTLN("DVM: failed to reserve ring buffer slot for pid %d", pid);
		return 0;
	}

	event->pid = pid;
	event->libraryType = libraryType(libId);
	event->loadTimeNs = bpf_ktime_get_ns();

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int dvmSchedProcessExit(void* ctx) {
	__u64 pidTgid = bpf_get_current_pid_tgid();
	__u32 tgid = pidTgid >> 32;
	__u32 tid  = (__u32)pidTgid;
	if (tgid != tid) {
		return 0;
	}
	bpf_map_delete_elem(&dvmSeenMap, &tgid);
	return 0;
}
