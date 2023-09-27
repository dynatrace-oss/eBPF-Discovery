// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "DataFunctions.h"

#include "TestDefine.h"

TEST_ENTRY int BPF_PROG(testDataProbeIsBeginningOfHttpRequest) {
	CHECK_TEST_RUNNER(runnerPid);

	if (inPtr != NULL && inLen < DISCOVERY_TEST_MAX_INPUT_LEN) {
		outRet = dataProbeIsBeginningOfHttpRequest(inPtr, inLen);
	}

	return 0;
}
