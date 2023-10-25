list(APPEND SOURCES src/Aggregator.cpp)
set(TARGET service)

add_library(${TARGET} STATIC ${SOURCES})
target_include_directories(${TARGET} PRIVATE src PUBLIC headers)

target_link_libraries(${TARGET} ebpfdiscoveryshared)
target_link_libraries(${TARGET} ebpfdiscovery)
target_link_libraries(${TARGET} httpparser)

if (BUILD_TESTS)
    list(APPEND TEST_SOURCES test/AggregatorTest.cpp)
    set(TEST_TARGET test${TARGET})

    add_executable(${TEST_TARGET} ${TEST_SOURCES})
    target_link_libraries(${TEST_TARGET} GTest::gtest_main GTest::gmock_main ${TARGET})
    target_include_directories(${TEST_TARGET} PRIVATE src)
    gtest_discover_tests(${TEST_TARGET})
endif ()
