set(PROTO_DIR_NAME ebpfdiscoveryproto)
set(SRC_DIR_NAME src)

list(
        APPEND
        PROTO_SOURCES
        ${PROTO_DIR_NAME}/service.proto
)

list(
        APPEND
        SOURCES
        ${SRC_DIR_NAME}/Translator.cpp
)

set(TARGET ebpfdiscoveryproto)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SOURCES})

add_library(${TARGET} STATIC ${PROTO_SRCS} ${SOURCES})
target_link_libraries(${TARGET} protobuf::libprotobuf)
target_link_libraries(${TARGET} service)
target_include_directories(${TARGET} PUBLIC ${CMAKE_CURRENT_BINARY_DIR} headers)

if (BUILD_TESTS)
    list(APPEND TEST_SOURCES test/TranslatorTest.cpp)
    set(TEST_TARGET test${TARGET})

    add_executable(${TEST_TARGET} ${TEST_SOURCES})
    target_link_libraries(${TEST_TARGET} GTest::gtest_main ${TARGET})
    target_include_directories(${TEST_TARGET} PRIVATE src)
    gtest_discover_tests(${TEST_TARGET})
endif ()