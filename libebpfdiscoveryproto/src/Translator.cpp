#include "ebpfdiscoveryproto/Translator.h"

#include <google/protobuf/util/json_util.h>

namespace proto {

ServicesList Translator::internalToProto(const std::vector<service::Service>& internalServices) {
	ServicesList external;
	for (const auto& i : internalServices) {
		const auto service{external.add_service()};

		service->set_pid(i.pid);
		service->set_endpoint(i.endpoint);
		service->set_internalclientsnumber(i.internalClientsNumber);
		service->set_externalclientsnumber(i.externalClientsNumber);
	}
	return external;
}

std::string Translator::protoToJson(const ServicesList& protoServices) {
	std::string json;
	google::protobuf::util::JsonPrintOptions options;
	options.add_whitespace = false;
	options.always_print_primitive_fields = false;
	options.preserve_proto_field_names = true;

	MessageToJsonString(protoServices, &json, options);
	return json;
}

} // namespace proto