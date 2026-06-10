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
#include "TestDefine.h"
#include "ProcessTracing.h"

size_t outCpuTime = 0;

SEC("fentry/do_nanosleep")
int BPF_PROG(testSlpFork) {
	CHECK_TEST_RUNNER(runnerPid);

	struct task_struct* task = (struct task_struct*)bpf_get_current_task();

	return handleProcessFork(task);
}

SEC("tracepoint/syscalls/sys_enter_getgid")
int BPF_PROG(testSlpExit) {
	CHECK_TEST_RUNNER(runnerPid);

	struct task_struct* task = (struct task_struct*)bpf_get_current_task();
	outCpuTime += BPF_CORE_READ(task, se.sum_exec_runtime);

	return handleProcessExit(task);
}
