// SPDX-License-Identifier: Apache-2.0

#include "ebpfdiscoveryproto/Translator.h"

#include <gtest/gtest.h>

using namespace proto;

class ProtobufTranslatorTest : public testing::Test {};

TEST_F(ProtobufTranslatorTest, successfulTranslationToJson) {

	std::vector<std::reference_wrapper<service::Service>> internalServices;
	service::Service service1{.pid = 1, .endpoint = "/endpoint/1", .internalClientsNumber = 1, .externalClientsNumber = 2};
	service::Service service2{.pid = 2, .endpoint = "/endpoint/1", .internalClientsNumber = 1, .externalClientsNumber = 2};
	service::Service service3{.pid = 3, .endpoint = "/endpoint/2", .internalClientsNumber = 1, .externalClientsNumber = 2};

	internalServices.push_back(service1);
	internalServices.push_back(service2);
	internalServices.push_back(service3);

	const auto proto{internalToProto(internalServices)};
	const auto result{protoToJson(proto)};
	const std::string expected{"{\"service\":[{\"pid\":1,\"endpoint\":\"/endpoint/"
							   "1\",\"internalClientsNumber\":1,\"externalClientsNumber\":2},{\"pid\":2,\"endpoint\":\"/endpoint/"
							   "1\",\"internalClientsNumber\":1,\"externalClientsNumber\":2},{\"pid\":3,\"endpoint\":\"/endpoint/"
							   "2\",\"internalClientsNumber\":1,\"externalClientsNumber\":2}]}"};
	EXPECT_EQ(result, expected);
}
