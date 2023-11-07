#include "ebpfdiscoveryproto/Translator.h"

#include <google/protobuf/util/json_util.h>

namespace proto {

ServicesList internalToProto(const std::vector<std::reference_wrapper<service::Service>>& services) {
	ServicesList protoServicesList;
	for (const auto& serviceRef : services) {
		const auto protoService{protoServicesList.add_service()};
		const auto& service{serviceRef.get()};

		protoService->set_pid(service.pid);
		protoService->set_endpoint(service.endpoint);
		protoService->set_internalclientsnumber(service.internalClientsNumber);
		protoService->set_externalclientsnumber(service.externalClientsNumber);
	}
	return protoServicesList;
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
