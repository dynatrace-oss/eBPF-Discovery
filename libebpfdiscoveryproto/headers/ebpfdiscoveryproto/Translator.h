// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ebpfdiscoveryproto/service.pb.h"
#include "service/Service.h"

#include <vector>

namespace proto {

class Translator {
public:
	static ServicesList internalToProto(const std::vector<service::Service>& internalServices);

	static std::string protoToJson(const ServicesList& protoServices);
};

} // namespace proto