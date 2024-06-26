# Copyright 2023 Dynatrace LLC
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

list(APPEND SOURCES
        src/Aggregator.cpp
        src/IpAddress.cpp
        src/IpAddressNetlinkChecker.cpp
        src/NetlinkCalls.cpp
        src/NetlinkSocket.cpp)

set(TARGET service)

add_library(${TARGET} STATIC ${SOURCES})
target_include_directories(${TARGET} PRIVATE src PUBLIC headers)

target_link_libraries(
    ${TARGET}
    PUBLIC
    ebpfdiscoveryshared
    httpparser
    logging
    CONAN_PKG::boost
    CONAN_PKG::ms-gsl
)

if (BUILD_TESTS)
    list(APPEND TEST_SOURCES
            test/AggregatorTest.cpp
            test/IpAddressCheckerTest.cpp
            test/IpAddressTest.cpp
            test/HttpRequestParserTest.cpp)
    set(TEST_TARGET test${TARGET})

    add_executable(${TEST_TARGET} ${TEST_SOURCES})
    target_link_libraries(${TEST_TARGET} CONAN_PKG::gtest ${TARGET})
    target_include_directories(${TEST_TARGET} PRIVATE src)
    gtest_discover_tests(${TEST_TARGET})
endif ()
