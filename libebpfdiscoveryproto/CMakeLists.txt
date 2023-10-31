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