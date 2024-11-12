/*
 * Copyright 2023 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ebpfdiscoveryproto/Translator.h"

#include <google/protobuf/util/json_util.h>

namespace proto {

std::pair<ServicesList, bool> internalToProto(const std::vector<std::reference_wrapper<service::Service>>& services, const bool enableNetworkCounters) {
	ServicesList protoServicesList;
	bool isListEmpty = true;
	for (const auto& serviceRef : services) {
		const auto& service{serviceRef.get()};

		if (service.internalClientsNumber == 0 && service.externalClientsNumber == 0) {
			continue;
		}

		const auto protoService{protoServicesList.add_service()};

		protoService->set_pid(service.pid);
		protoService->set_endpoint(service.endpoint);
		protoService->set_domain(service.domain);
		protoService->set_scheme(service.scheme);
		protoService->set_internalclientsnumber(service.internalClientsNumber);
		protoService->set_externalclientsnumber(service.externalClientsNumber);
		if (enableNetworkCounters) {
			protoService->set_externalipv4_16clientnets(service.detectedExternalIPv416Networks.size());
			protoService->set_externalipv4_24clientnets(service.detectedExternalIPv424Networks.size());
			protoService->set_externalipv6clientsnets(service.detectedExternalIPv6Networks.size());
		}

		isListEmpty = false;
	}
	return {protoServicesList, isListEmpty};
}

std::string protoToJson(const ServicesList& protoServices) {
	std::string json;
	google::protobuf::util::JsonPrintOptions options;
	options.add_whitespace = false;
	options.always_print_primitive_fields = false;
	options.preserve_proto_field_names = true;

	MessageToJsonString(protoServices, &json, options);
	return json;
}

} // namespace proto
