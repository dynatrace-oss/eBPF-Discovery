// SPDX-License-Identifier: Apache-2.0

#include "ebpfdiscoveryproto/Translator.h"

#include <gtest/gtest.h>

using namespace proto;

struct ProtobufTranslatorTest : public testing::Test {
	Translator translator;
	const std::string expectedServicesJson{
			"{\"service\":[{\"pid\":1,\"endpoint\":\"/endpoint/"
			"1\",\"internalClientsNumber\":1,\"externalClientsNumber\":2},{\"pid\":2,\"endpoint\":\"/endpoint/"
			"1\",\"internalClientsNumber\":1,\"externalClientsNumber\":2},{\"pid\":3,\"endpoint\":\"/endpoint/"
			"2\",\"internalClientsNumber\":1,\"externalClientsNumber\":2}]}"};
	std::vector<service::Service> internalServices;

	void SetUp() override {
		internalServices.emplace_back(
				service::Service{.pid = 1, .endpoint = "/endpoint/1", .internalClientsNumber = 1, .externalClientsNumber = 2});
		internalServices.emplace_back(
				service::Service{.pid = 2, .endpoint = "/endpoint/1", .internalClientsNumber = 1, .externalClientsNumber = 2});
		internalServices.emplace_back(
				service::Service{.pid = 3, .endpoint = "/endpoint/2", .internalClientsNumber = 1, .externalClientsNumber = 2});
	}
};

TEST_F(ProtobufTranslatorTest, successfulTranslation) {
	auto proto = translator.internalToProto(internalServices);
	auto json = translator.protoToJson(proto);
	EXPECT_EQ(json, expectedServicesJson);
}