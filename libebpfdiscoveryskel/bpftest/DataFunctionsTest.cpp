// SPDX-License-Identifier: GPL-2.0
#include "discoveryTest.h"

#include "discoveryTest.skel.h"

#include <gtest/gtest.h>

class DataProbeIsBeginningOfHttpRequestTest : public ebpfdiscovery::bpftest::DiscoveryTest {};

using ebpfdiscovery::bpftest::attachBpfProgram;
using ebpfdiscovery::bpftest::triggerTracepoint;

TEST_F(DataProbeIsBeginningOfHttpRequestTest, testValidGETLine) {
	const std::string in{"GET / HTTP/1.1\r\n"};
	const size_t len{in.length()};

	setInPtr(in);
	setInLen(len);

	attachBpfProgram(testSkel->progs.testDataProbeIsBeginningOfHttpRequest);
	triggerTracepoint();

	EXPECT_TRUE(getOutRet());
}

TEST_F(DataProbeIsBeginningOfHttpRequestTest, testValidPOSTLine) {
	const std::string in{"POST / HTTP/1.1\r\n"};
	const size_t len{in.length()};

	setInPtr(in);
	setInLen(len);

	attachBpfProgram(testSkel->progs.testDataProbeIsBeginningOfHttpRequest);
	triggerTracepoint();

	EXPECT_TRUE(getOutRet());
}

TEST_F(DataProbeIsBeginningOfHttpRequestTest, testInvalidLine) {
	const std::string in{"get / HTTP/1.1\r\n"};
	const size_t len{in.length()};

	setInPtr(in);
	setInLen(len);

	attachBpfProgram(testSkel->progs.testDataProbeIsBeginningOfHttpRequest);
	triggerTracepoint();

	EXPECT_FALSE(getOutRet());
}
