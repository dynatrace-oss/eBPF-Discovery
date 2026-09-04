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

#include "ebpfdiscovery/Dvm.h"
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
} // namespace

class DvmMock : public Dvm {
public:
	using Dvm::Dvm;
	MOCK_METHOD(dvm_bpf*, openBpf, (const bpf_object_open_opts&), (override));
	MOCK_METHOD(int, loadBpf, (dvm_bpf*), (override));
	MOCK_METHOD(void, destroyBpf, (dvm_bpf*), (override));
};

class DvmTest : public Test {
public:
	DvmTest() {
		auto libBpfParam = std::make_unique<LibBpfInterfaceMock>();
		libBpfMock = libBpfParam.get();
		tested = std::make_unique<StrictMock<DvmMock>>(std::move(libBpfParam));

		fakeSkel.maps.dvmEvents = reinterpret_cast<bpf_map*>(21);
		fakeSkel.progs.dvmVfsOpenHook = reinterpret_cast<bpf_program*>(34);
		fakeSkel.progs.dvmSchedProcessExit = reinterpret_cast<bpf_program*>(78);
	}

	void checkJsonResult(const std::string& json, const std::vector<DvmEvent>& events) {
		try {
			EXPECT_FALSE(json.empty());
			EXPECT_TRUE(isParsableJson(json));

			const auto& parsedJson = boost::json::parse(json);
			const auto& loads = parsedJson.as_object().at("libraryLoads");
			int index = 0;
			for (const auto& elem : loads.as_array()) {
				const auto& load = elem.as_object();
				EXPECT_EQ(3u, load.size());

				ASSERT_TRUE(load.contains("pid"));
				EXPECT_EQ(load.at("pid"), events[index].pid);

				ASSERT_TRUE(load.contains("libraryType"));
				EXPECT_EQ(load.at("libraryType"), events[index].libraryType);

				ASSERT_TRUE(load.contains("loadTs"));
				index++;
			}
		} catch (const std::exception& e) {
			FAIL() << e.what();
		}
	}

	void loadMockedBpf() {
		EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
		EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
		EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmVfsOpenHook)).WillOnce(Return(fakeProgramLink));
		EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmSchedProcessExit)).WillOnce(Return(fakeProgramLink));
		EXPECT_CALL(*libBpfMock, getMapFd(fakeSkel.maps.dvmEvents)).WillOnce(Return(fakeMapFd));
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
	dvm_bpf fakeSkel{};
	LibBpfInterfaceMock* libBpfMock;
	std::unique_ptr<StrictMock<DvmMock>> tested;
};

TEST_F(DvmTest, basic) {
	loadMockedBpf();

	std::vector<DvmEvent> events{
		{.loadTimeNs = 1'000'000'000ULL, .pid = 100, .libraryType = DVM_LIBRARY_TYPE_JVM},
		{.loadTimeNs = 2'000'000'000ULL, .pid = 200, .libraryType = DVM_LIBRARY_TYPE_DOTNET},
	};

	std::streambuf* const origBuf{std::cout.rdbuf()};
	std::ostringstream captured;
	std::cout.rdbuf(captured.rdbuf());

	for (auto& event : events) {
		addEventToBuffer(tested.get(), &event, 0);
	}
	EXPECT_CALL(*libBpfMock, pollEvents(fakeBuffer, 0));
	tested->collectAndOutput();
	const std::string firstOutput{captured.str()};

	captured.str("");
	EXPECT_CALL(*libBpfMock, pollEvents(fakeBuffer, 0));
	tested->collectAndOutput();
	const std::string secondOutput{captured.str()};

	std::cout.rdbuf(origBuf);

	checkJsonResult(firstOutput, events);
	EXPECT_EQ(secondOutput, std::string{});

	unloadMockedBpf();
}

TEST_F(DvmTest, openBpfFails) {
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(nullptr));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	tested->unload();
}

TEST_F(DvmTest, loadBpfFails) {
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(-1));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}

TEST_F(DvmTest, attachVfsOpenFails) {
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmVfsOpenHook)).WillOnce(Return(nullptr));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}

TEST_F(DvmTest, attachSchedProcessExitFails) {
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmVfsOpenHook)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmSchedProcessExit)).WillOnce(Return(nullptr));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}

TEST_F(DvmTest, getMapFdFails) {
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmVfsOpenHook)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmSchedProcessExit)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, getMapFd(fakeSkel.maps.dvmEvents)).WillOnce(Return(-EINVAL));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}

TEST_F(DvmTest, createRingBufferFails) {
	EXPECT_CALL(*tested, openBpf(_)).WillOnce(Return(&fakeSkel));
	EXPECT_CALL(*tested, loadBpf(&fakeSkel)).WillOnce(Return(0));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmVfsOpenHook)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, attachProgram(fakeSkel.progs.dvmSchedProcessExit)).WillOnce(Return(fakeProgramLink));
	EXPECT_CALL(*libBpfMock, getMapFd(fakeSkel.maps.dvmEvents)).WillOnce(Return(fakeMapFd));
	EXPECT_CALL(*libBpfMock, createRingBuffer(fakeMapFd, _, tested.get(), nullptr)).WillOnce(Return(nullptr));
	EXPECT_THROW(tested->load(opts), std::runtime_error);

	EXPECT_CALL(*tested, destroyBpf(&fakeSkel));
	tested->unload();
}
