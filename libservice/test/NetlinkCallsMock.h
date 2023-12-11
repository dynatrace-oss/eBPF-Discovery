// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <gmock/gmock.h>

#include "service/NetlinkCalls.h"

namespace service {

class NetlinkCallsMock : public NetlinkCalls {
public:
	MOCK_CONST_METHOD0(collectIpInterfaces, IpInterfaces());
	MOCK_CONST_METHOD0(collectBridgeIndices, BridgeIndices());
};

} // namespace service
