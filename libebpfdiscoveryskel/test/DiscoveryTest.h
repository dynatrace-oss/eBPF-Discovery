// SPDX-License-Identifier: GPL-2.0
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
		inPtrData.clear();
		std::copy(str.begin(), str.end(), std::back_inserter(inPtrData));
		testBss->inPtr = inPtrData.data();
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

	discoveryTest_bpf* testSkel;
	discoveryTest_bpf::discoveryTest_bpf__bss* testBss;

	std::vector<char> inPtrData;

	void checkLoaded() {
		if (!isLoaded()) {
			throw std::runtime_error("DiscoveryTest is uninitialized");
		}
	}
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
