/*
* Copyright 2023 Dynatrace LLC
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

#include "DiscoveryTest.h"

#include "discoveryTest.skel.h"

#include <gtest/gtest.h>
#include "ebpfdiscoveryshared/SlpTypes.h"

#include <cstring>
#include <thread>

using ebpfdiscovery::bpftest::attachBpfProgram;
using ebpfdiscovery::bpftest::DiscoveryTest;

SlpEvent lastEvent;

static int handle_event(void*, void* data, size_t) {
	struct SlpEvent* event = (struct SlpEvent*)data;
	lastEvent.pid = event->pid;
	lastEvent.parentPid = event->parentPid;
	lastEvent.cpuTimeNs = event->cpuTimeNs;
	return 0;
}

class SlpBpfTest : public DiscoveryTest {
public:
	void SetUp() override {
		DiscoveryTest::SetUp();
		rb = ring_buffer__new(bpf_map__fd(testSkel->maps.slpEvents), handle_event, nullptr, nullptr);
		threadsMapFd = bpf_map__fd(testSkel->maps.slpThreadsData);

		attachBpfProgram(testSkel->progs.testSlpFork);
		attachBpfProgram(testSkel->progs.testSlpExit);
	}

	void TearDown() override {
		ring_buffer__free(rb);
		DiscoveryTest::TearDown();
	}

	void triggerForkTracepoint() {
		usleep(1);
	}

	void triggerExitTracepoint() {
		(void)getgid();
	}

	void checkEventsBufIsEmpty() {
		int ret = ring_buffer__poll(rb, 10);
		ASSERT_EQ(ret, 0);
	}

	void checkThreadsCount(std::optional<__u32> threadsCount) {
		const int pid = getpid();
		SlpThreadsData val{};
		const int ret = bpf_map_lookup_elem(threadsMapFd, &pid, &val);
		if (threadsCount) {
			ASSERT_EQ(ret, 0);
			EXPECT_EQ(val.count, *threadsCount);
		}else {
			ASSERT_NE(ret, 0);
		}
	}

	void resetThreadsCount() {
		const int pid = getpid();
		SlpThreadsData val{
			.count = 0,
			.cpuTime = 0,
		};
		int ret = bpf_map_update_elem(threadsMapFd, &pid, &val, 0);
		ASSERT_EQ(ret, 0);
	}

	void checkResult() {
		checkLoaded();

		const int ret = ring_buffer__poll(rb, 100);
		ASSERT_EQ(ret, 1);
		EXPECT_EQ(lastEvent.pid, getpid());
		EXPECT_EQ(lastEvent.parentPid, getppid());
		EXPECT_EQ(lastEvent.cpuTimeNs, testBss->outCpuTime);
		//startTimeNs not checked because it is too much hassle to get start time in ns from user space

		checkEventsBufIsEmpty();
		checkThreadsCount(std::nullopt);
	}

	ring_buffer* rb = nullptr;
	int threadsMapFd = -1;
};

TEST_F(SlpBpfTest, basic) {
	triggerForkTracepoint();
	checkEventsBufIsEmpty();
	triggerExitTracepoint();
	checkResult();
}

TEST_F(SlpBpfTest, multipleForks) {
	triggerForkTracepoint();
	checkEventsBufIsEmpty();
	triggerForkTracepoint();
	checkEventsBufIsEmpty();
	triggerExitTracepoint();
	checkEventsBufIsEmpty();
	triggerExitTracepoint();
	checkResult();
}

TEST_F(SlpBpfTest, exitWithoutFork) {
	triggerExitTracepoint();
	checkEventsBufIsEmpty();
}

TEST_F(SlpBpfTest, checkInvalidThreadsCount) {
	triggerForkTracepoint();
	checkEventsBufIsEmpty();
	checkThreadsCount(1);

	resetThreadsCount();

	triggerExitTracepoint();
	checkEventsBufIsEmpty();
	checkThreadsCount(std::nullopt);
}

TEST_F(SlpBpfTest, strayThreadsAreNotRecorded) {
	std::thread thread{[this]() {
		triggerForkTracepoint();
	}};
	thread.join();
	checkThreadsCount(std::nullopt);
	triggerExitTracepoint();
	checkEventsBufIsEmpty();
}