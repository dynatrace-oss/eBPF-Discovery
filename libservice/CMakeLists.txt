list(APPEND SOURCES src/Aggregator.cpp)
set(TARGET service)

add_library(${TARGET} STATIC ${SOURCES})
target_include_directories(${TARGET} PRIVATE src PUBLIC headers)

target_link_libraries(${TARGET} PUBLIC ebpfdiscoveryshared ebpfdiscovery httpparser CONAN_PKG::boost)

if (BUILD_TESTS)
    list(APPEND TEST_SOURCES test/AggregatorTest.cpp)
    set(TEST_TARGET test${TARGET})

    add_executable(${TEST_TARGET} ${TEST_SOURCES})
    target_link_libraries(${TEST_TARGET} CONAN_PKG::gtest ${TARGET})
    target_include_directories(${TEST_TARGET} PRIVATE src)
    gtest_discover_tests(${TEST_TARGET})
endif ()
