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

#include "DiscoveryTestConstants.h"

#include "discoveryTest.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <gtest/gtest.h>

namespace ebpfdiscovery::bpftest {

class DiscoveryTest : public ::testing::Test {
public:
	DiscoveryTest() : testSkel{nullptr}, testBss{nullptr} {
	}

	bool isLoaded() {
		return testSkel != nullptr && testBss != nullptr;
	}

	void setInPtr(const std::string& str) {
		checkLoaded();
		inPtrSrc.clear();
		std::copy(str.begin(), str.end(), std::back_inserter(inPtrSrc));
		testBss->inPtr = inPtrSrc.data();
	}

	void setInLen(size_t len) {
		checkLoaded();
		testBss->inLen = len;
	}

	int getOutRet() {
		checkLoaded();
		return testBss->outRet;
	}

protected:
	void SetUp() override {
		testSkel = discoveryTest_bpf__open_and_load();
		if (testSkel == nullptr) {
			GTEST_SKIP() << "Couldn't open and load BPF object for test execution.";
		}

		testBss = testSkel->bss;
		testBss->runnerPid = getpid();
	}

	void TearDown() override {
		if (testSkel != nullptr) {
			discoveryTest_bpf__destroy(testSkel);
		}
	}

	void checkLoaded() {
		if (!isLoaded()) {
			throw std::runtime_error("DiscoveryTest is uninitialized");
		}
	}

	discoveryTest_bpf* testSkel;
	discoveryTest_bpf::discoveryTest_bpf__bss* testBss;

	std::vector<char> inPtrSrc;
};

void attachBpfProgram(bpf_program* prog) {
	auto link = bpf_program__attach(prog);
	if (link == nullptr) {
		throw std::runtime_error("couldn't attach bpf program");
	}
}

void triggerTracepoint() {
	usleep(1);
}

} // namespace ebpfdiscovery::bpftest
