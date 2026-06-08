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

#pragma once

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "ebpfdiscoveryshared/SlpTypes.h"
#include  "DebugPrint.h"

#define MAX_EVENTS 180000

struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_EVENTS);
} slpEvents SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENTS + MAX_EVENTS / 10); // +10% for non-slp processes
    __type(key, __u32);
    __type(value, struct SlpThreadsData);
}slpThreadsData SEC(".maps");

__attribute__((always_inline)) inline static int handleProcessExit(struct task_struct* task) {
	if (!task) return 0;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	struct SlpThreadsData* elem = bpf_map_lookup_elem(&slpThreadsData, &tgid);
	if (!elem) {
		return 0;
	}

	__u64 threadCpuTime = BPF_CORE_READ(task, se.sum_exec_runtime);
	__u64 processCpuTime = __sync_add_and_fetch(&elem->cpuTime, threadCpuTime);
	//this may be unnecessary, but I couldn't find 100% trustworthy source to confirm it
	barrier();
	__s64 threadsCount = __sync_sub_and_fetch(&elem->count, 1);

	if(threadsCount > 0){
		return 0;
	}

	bpf_map_delete_elem(&slpThreadsData, &tgid);

	if(threadsCount < 0){
		DEBUG_PRINTLN("Invalid thread count value %d for process %d", threadsCount, tgid);
		return (int)threadsCount;
	}

	struct SlpEvent* event = bpf_ringbuf_reserve(&slpEvents, sizeof(struct SlpEvent), 0);
	if(!event) {
		DEBUG_PRINTLN("Failed to allocate event for process %d", tgid);
		return 0;
	}

	event->pid = tgid;
	event->parentPid = BPF_CORE_READ(task, parent, pid);
	event->cpuTimeNs = processCpuTime;
	event->startTimeNs = BPF_CORE_READ(task, start_time);
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int processExitHook(struct trace_event_raw_sched_process_template* ctx){
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

	return handleProcessExit(task);
}

__attribute__((always_inline)) inline static int handleProcessFork(struct task_struct* task) {
	if (!task) return 0;

	const __u32 tgid = BPF_CORE_READ(task, tgid);
	const __u32 pid = BPF_CORE_READ(task, pid);
	const __u32 parentPid = BPF_CORE_READ(task, parent, pid);

	const bool isKThread = parentPid == 0 || parentPid == 2;
	struct SlpThreadsData* elem = bpf_map_lookup_elem(&slpThreadsData, &tgid);
	if(elem){
		__sync_fetch_and_add(&elem->count, 1);
	}
	// skip kthreads (parent 0 or 2), for other threads add new entry only if it is new process, skip threads for already running processes
	else if (!isKThread && pid == tgid) {
		struct SlpThreadsData data;
		data.count = 1;
		data.cpuTime = 0;
		bpf_map_update_elem(&slpThreadsData, &tgid, &data, BPF_ANY);
	}

	return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int processForkHook(struct bpf_raw_tracepoint_args* ctx){
    struct task_struct* child = (struct task_struct*)ctx->args[1];

	return handleProcessFork(child);
}
