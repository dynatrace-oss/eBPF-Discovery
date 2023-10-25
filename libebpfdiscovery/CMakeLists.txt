list(
        APPEND
        SOURCES
        src/Config.cpp
        src/Discovery.cpp
        src/DiscoveryBpf.cpp
        src/DiscoveryBpfLoader.cpp
        src/IpAddressChecker.cpp
        src/NetlinkCalls.cpp
        src/Session.cpp
        src/StringFunctions.cpp
)
set(TARGET ebpfdiscovery)

add_library(${TARGET} STATIC ${SOURCES})

target_include_directories(${TARGET} PRIVATE src PUBLIC headers)

target_link_libraries(${TARGET} bpfload)
target_link_libraries(${TARGET} ebpfdiscoveryproto)
target_link_libraries(${TARGET} ebpfdiscoveryshared)
target_link_libraries(${TARGET} ebpfdiscoveryskel)
target_link_libraries(${TARGET} fmt::fmt)
target_link_libraries(${TARGET} httpparser)
target_link_libraries(${TARGET} logging)
target_link_libraries(${TARGET} spdlog::spdlog)
target_link_libraries(${TARGET} service)

if (BUILD_TESTS)
    list(APPEND TEST_SOURCES test/StringFunctionsTest.cpp test/LRUCacheTest.cpp test/IpAddressCheckerTest.cpp)
    set(TEST_TARGET test${TARGET})

    add_executable(${TEST_TARGET} ${TEST_SOURCES})
    target_link_libraries(${TEST_TARGET} GTest::gtest_main GTest::gmock_main ${TARGET})
    target_include_directories(${TEST_TARGET} PRIVATE src)
    gtest_discover_tests(${TEST_TARGET})
endif ()
