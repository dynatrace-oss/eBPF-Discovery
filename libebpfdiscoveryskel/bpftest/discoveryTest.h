// SPDX-License-Identifier: GPL-2.0
#pragma once

#define DISCOVERY_TEST_MAX_INPUT_LEN 1024

#ifdef __cplusplus

#	include "discoveryTest.skel.h"

#	include <bpf/bpf.h>
#	include <bpf/libbpf.h>

#	include <gtest/gtest.h>

namespace ebpfdiscovery::bpftest {

class DiscoveryTest : public ::testing::Test {
public:
	DiscoveryTest() : testSkel{nullptr}, testBss{nullptr} {
	}

	void setInPtr(const std::string& str) {
		inPtrSrc.clear();
		std::copy(str.begin(), str.end(), std::back_inserter(inPtrSrc));
		testBss->inPtr = inPtrSrc.data();
	}

	void setInLen(size_t len) {
		testBss->inLen = len;
	}

	int getOutRet() {
		return testBss->outRet;
	}

protected:
	void SetUp() override {
		testSkel = discoveryTest_bpf__open_and_load();
		if (testSkel == nullptr) {
			throw std::runtime_error("couldn't open and load bpf object");
		}

		testBss = testSkel->bss;
		testBss->runnerPid = getpid();
	}

	void TearDown() override {
		discoveryTest_bpf__destroy(testSkel);
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

#endif // __cplusplus
