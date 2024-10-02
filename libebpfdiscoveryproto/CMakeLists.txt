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

set(TARGET ebpfdiscoveryproto)

list(APPEND SOURCES src/Translator.cpp)

set(PROTO_FILES_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ebpfdiscoveryproto)

file(GLOB PROTO_FILES "${PROTO_FILES_DIRECTORY}/*.proto")

set(GENERATED_PROTO_FILES "")
foreach(PROTO_FILE ${PROTO_FILES})
	get_filename_component(PROTO_FILE_NAME ${PROTO_FILE} NAME_WE)

	set(PROTO_C_FILE "${CMAKE_CURRENT_BINARY_DIR}/ebpfdiscoveryproto/${PROTO_FILE_NAME}.pb.cc")
	set(PROTO_H_FILE "${CMAKE_CURRENT_BINARY_DIR}/ebpfdiscoveryproto/${PROTO_FILE_NAME}.pb.h")

	add_custom_command(
			OUTPUT ${PROTO_C_FILE} ${PROTO_H_FILE}
			COMMAND ${CONAN_BIN_DIRS_PROTOBUF}/protoc
			ARGS --cpp_out=${CMAKE_CURRENT_BINARY_DIR} --proto_path=${CMAKE_CURRENT_SOURCE_DIR} ${PROTO_FILE}
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			DEPENDS ${PROTO_FILE}
	)
	list(APPEND GENERATED_FILES ${PROTO_C_FILE})
endforeach()

add_library(${TARGET} STATIC ${SOURCES} ${GENERATED_FILES})
target_link_libraries(${TARGET} CONAN_PKG::protobuf)
target_link_libraries(${TARGET} service)
target_include_directories(${TARGET} PUBLIC ${CMAKE_CURRENT_BINARY_DIR} headers)

if (BUILD_TESTS)
    list(APPEND TEST_SOURCES test/TranslatorTest.cpp)
    set(TEST_TARGET test${TARGET})

    add_executable(${TEST_TARGET} ${TEST_SOURCES})
    target_link_libraries(${TEST_TARGET} CONAN_PKG::gtest ${TARGET})
    target_include_directories(${TEST_TARGET} PRIVATE src)
    gtest_discover_tests(${TEST_TARGET})
endif ()