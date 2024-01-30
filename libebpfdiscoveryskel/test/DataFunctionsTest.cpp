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
