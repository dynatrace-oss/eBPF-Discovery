// SPDX-License-Identifier: GPL-2.0
#include "DiscoveryTest.h"

#include "discoveryTest.skel.h"

#include <gtest/gtest.h>

#include <optional>
#include <tuple>
#include <variant>

using ebpfdiscovery::bpftest::attachBpfProgram;
using ebpfdiscovery::bpftest::DiscoveryTest;
using ebpfdiscovery::bpftest::triggerTracepoint;

struct DiscoveryDataFunctionsTestParams {
	std::string inputPtrData;
	size_t inputLen;
	int expectedRet;
};

class DiscoveryDataFunctionsTest : public DiscoveryTest, public ::testing::WithParamInterface<DiscoveryDataFunctionsTestParams> {};
class DataProbeIsBeginningOfHttpRequestTest : public DiscoveryDataFunctionsTest {};

TEST_P(DataProbeIsBeginningOfHttpRequestTest, Default) {
	const auto& data{GetParam()};
	setInPtr(data.inputPtrData);
	setInLen(data.inputLen);

	attachBpfProgram(testSkel->progs.testDataProbeIsBeginningOfHttpRequest);
	triggerTracepoint();

	EXPECT_EQ(getOutRet(), data.expectedRet);
}

INSTANTIATE_TEST_SUITE_P(
		Default,
		DataProbeIsBeginningOfHttpRequestTest,
		::testing::Values(DiscoveryDataFunctionsTestParams{
				.inputPtrData = std::string("GET / HTTP/1.1\r\n"), .inputLen = 16, .expectedRet = (int)true}));
