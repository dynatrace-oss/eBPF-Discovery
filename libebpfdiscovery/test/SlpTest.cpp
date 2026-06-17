/*
* Copyright 2026 Dynatrace LLC
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

#include "ebpfdiscovery/Slp.h"
#include "ebpfdiscovery/Discovery.h"
#include "LibBpInterfaceMock.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <boost/json.hpp>
#include <sstream>
#include <string>
#include <vector>

using namespace ebpfdiscovery;
using namespace ::testing;

namespace {
bool isParsableJson(const std::string& s) {
	boost::system::error_code ec;
	boost::json::parse(s, ec);
	return !ec;
}
}

class SlpMock : public Slp {
public:
	using Slp::Slp;
	MOCK_METHOD(slp_bpf*, openBpf, (const bpf_object_open_opts&), (override));
	MOCK_METHOD(int, loadBpf, (slp_bpf*), (override));
	MOCK_METHOD(void, destroyBpf, (slp_bpf*), (override));
};

class SlpTest : public Test {
public:
	SlpTest() {
		auto LibBpfParam = std::make_unique<LibBpfInterfaceMock>();
		libBpfMock = LibBpfParam.get();
		tested = std::make_unique<StrictMock<SlpMock>>(std::move(LibBpfParam));

		//this values will never be dereferenced, they are used only in mock parameters comparison, so
		//it is safe to use invalid pointers
		fakeSkel.maps.slpEvents = reinterpret_cast<bpf_map*>(21);
		fakeSkel.progs.processExitHook = reinterpret_cast<bpf_program*>(34);
		fakeSkel.progs.processForkHook = reinterpret_cast<bpf_program*>(78);
	}

	void checkJsonResult(const std::string& json, const std::vector<SlpEvent>& events) {
		try {
			EXPECT_FALSE(json.empty());
			EXPECT_TRUE(isParsableJson(json));

			const auto& parsedJson = boost::json::parse(json);
			const auto& processes = parsedJson.as_object().at("processes");
			int index = 0;
			for ( const auto& elem : processes.as_array()) {
				const auto& process = elem.as_object();
				EXPECT_EQ(4u, process.size());

				ASSERT_TRUE(process.contains("pid"));
				EXPECT_EQ(process.at("pid"), events[index].pid);

				ASSERT_TRUE(process.contains("ppid"));
				EXPECT_EQ(process.at("ppid"), events[index].parentPid);

				ASSERT_TRUE(process.contains("startTs"));
				EXPECT_EQ(process.at("startTs"), nsToTicks(events[index].startTimeNs));

				ASSERT_TRUE(process.contains("cpuTime"));
				EXPECT_EQ(process.at("cpuTime"), nsToTicks(events[index].cpuTimeNs));
				index++;
			}
		} catch (const std::exception& e) {
			FAIL() << e.what();
		}
	}

	void loadMockedBpf() {
		EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
		EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
		EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processForkHook)).WillOnce(Return(fakeProgramLink));
		EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processExitHook)).WillOnce(Return(fakeProgramLink));
		EXPECT_CALL(*libBpfMock, getMapFd(fakeSkel.maps.slpEvents)).WillOnce(Return(fakeMapFd));
		EXPECT_CALL(*libBpfMock, createRingBuffer(fakeMapFd, _, tested.get(), nullptr)).WillOnce(DoAll(SaveArg<1>(&addEventToBuffer), Return(fakeBuffer)));
		tested->load(opts);
	}

	void unloadMockedBpf() {
		EXPECT_CALL(*libBpfMock, freeRingBuffer(fakeBuffer));
		EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
		tested->unload();
	}

	bpf_link* fakeProgramLink = reinterpret_cast<bpf_link*>(0xBADADD);
	ring_buffer* fakeBuffer = reinterpret_cast<ring_buffer*>(0xDEADBEEF);
	const int fakeMapFd = 13;

	ring_buffer_sample_fn addEventToBuffer;
	bpf_object_open_opts opts{};
	slp_bpf fakeSkel{};
	LibBpfInterfaceMock* libBpfMock;
	std::unique_ptr<StrictMock<SlpMock>> tested;
};

TEST_F(SlpTest, basic) {
	loadMockedBpf();

	std::vector<SlpEvent> processes{
		{.pid = 10, .parentPid = 1, .startTimeNs = 42'102'304'506ULL, .cpuTimeNs = 7'000'345'000ULL},
		{.pid = 15, .parentPid = 21, .startTimeNs = 555'123'456'789ULL, .cpuTimeNs = 321'000'000'000ULL},
	};

	// Capture stdout
	std::streambuf* const origBuf{std::cout.rdbuf()};
	std::ostringstream captured;
	std::cout.rdbuf(captured.rdbuf());

	//reading from ring_buffer is mocked so we have to manually call handler function
	for (auto& event : processes) {
		addEventToBuffer(tested.get(), &event, 0);
	}
	EXPECT_CALL(*libBpfMock, pollEvents(fakeBuffer, 0));
	tested->collectAndOutput();
	const std::string firstOutput{captured.str()};

	//no processes are added since last call to collectAndOutput, so the second call to collectAndOutput should produce empty output
	captured.str("");
	EXPECT_CALL(*libBpfMock, pollEvents(fakeBuffer, 0));
	tested->collectAndOutput();
	const std::string secondOutput{captured.str()};

	std::cout.rdbuf(origBuf);

	checkJsonResult(firstOutput, processes);
	EXPECT_EQ(secondOutput, std::string{});

	unloadMockedBpf();
}

TEST_F(SlpTest, openBpfFails) {
	using namespace ::testing;
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(nullptr));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	//unload does nothing when opening bpf failed, so no EXPECT_CALLs
	tested->unload();
}

TEST_F(SlpTest, loadBpfFails) {
	using namespace ::testing;
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(-1));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}

TEST_F(SlpTest, attachForkProgramFails) {
	using namespace ::testing;
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processForkHook)).WillOnce(Return(nullptr));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}

TEST_F(SlpTest, attachExitProgramFails) {
	using namespace ::testing;
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processForkHook)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processExitHook)).WillOnce(Return(nullptr));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}

TEST_F(SlpTest, getMapFdFails) {
	using namespace ::testing;
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processForkHook)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processExitHook)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, getMapFd(fakeSkel.maps.slpEvents)).WillOnce(Return(-EINVAL));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}

TEST_F(SlpTest, createRingBufferFails) {
	using namespace ::testing;
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processForkHook)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.processExitHook)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, getMapFd(fakeSkel.maps.slpEvents)).WillOnce(Return(fakeMapFd));
	EXPECT_CALL(*libBpfMock, createRingBuffer(fakeMapFd, _, tested.get(), nullptr)).WillOnce(Return(nullptr));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}




