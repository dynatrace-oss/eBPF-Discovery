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

#include <gtest/gtest.h>

using namespace proto;

class ProtobufTranslatorTest : public testing::Test {};

TEST_F(ProtobufTranslatorTest, successfulTranslationToJson) {

	std::vector<std::reference_wrapper<service::Service>> internalServices;
	service::Service service1{.pid = 1, .endpoint = "/endpoint/1", .internalClientsNumber = 1, .externalClientsNumber = 2};
	service::Service service2{.pid = 2, .endpoint = "/endpoint/1", .internalClientsNumber = 1, .externalClientsNumber = 2};
	service::Service service3{.pid = 3, .endpoint = "/endpoint/2", .internalClientsNumber = 1, .externalClientsNumber = 2};

	service::Service service4{.pid = 4, .endpoint = "google.com/endpoint/3", .internalClientsNumber = 1, .externalClientsNumber = 2, .domain = "google.com", .scheme = "http"};
	service::Service service5{.pid = 5, .endpoint = "dynatrace.com/endpoint/4", .internalClientsNumber = 1, .externalClientsNumber = 2, .domain = "dynatrace.com", .scheme = "https"};

	internalServices.push_back(service1);
	internalServices.push_back(service2);
	internalServices.push_back(service3);
	internalServices.push_back(service4);
	internalServices.push_back(service5);

	const auto proto{internalToProto(internalServices)};
	const auto result{protoToJson(proto)};
	const std::string expected{"{\"service\":[{\"pid\":1,\"endpoint\":\"/endpoint/"
							   "1\",\"internalClientsNumber\":1,\"externalClientsNumber\":2},{\"pid\":2,\"endpoint\":\"/endpoint/"
							   "1\",\"internalClientsNumber\":1,\"externalClientsNumber\":2},{\"pid\":3,\"endpoint\":\"/endpoint/"
							   "2\",\"internalClientsNumber\":1,\"externalClientsNumber\":2},{\"pid\":4,\"endpoint\":\"google.com/"
							   "endpoint/3\",\"internalClientsNumber\":1,\"externalClientsNumber\":2,\"domain\":\"google.com\",\"scheme\":\"http\"},{\"pid\":5,\"endpoint\":\"dynatrace.com/"
							   "endpoint/4\",\"internalClientsNumber\":1,\"externalClientsNumber\":2,\"domain\":\"dynatrace.com\",\"scheme\":\"https\"}]}"};
	EXPECT_EQ(result, expected);
}
