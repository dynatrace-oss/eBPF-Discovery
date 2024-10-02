# Copyright 2024 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

list(APPEND SOURCES src/Logger.cpp src/Formatting.cpp)
set(TARGET logging)

add_library(${TARGET} STATIC ${SOURCES})
target_include_directories(${TARGET} PRIVATE src PUBLIC headers)

target_link_libraries(${TARGET} CONAN_PKG::spdlog CONAN_PKG::boost)

if(BUILD_TESTS)
	list(APPEND TEST_SOURCES test/FormattingTest.cpp)
	set(TEST_TARGET test${TARGET})

	add_executable(${TEST_TARGET} ${TEST_SOURCES})
	target_link_libraries(${TEST_TARGET} CONAN_PKG::gtest CONAN_PKG::boost ${TARGET})
	target_include_directories(${TEST_TARGET} PRIVATE src)
	gtest_discover_tests(${TEST_TARGET})
endif()
