// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ebpfdiscoveryproto/service.pb.h"
#include "service/Service.h"

#include <vector>

namespace proto {

ServicesList internalToProto(const std::vector<service::Service>& internalServices);

std::string protoToJson(const ServicesList& protoServices);

} // namespace proto