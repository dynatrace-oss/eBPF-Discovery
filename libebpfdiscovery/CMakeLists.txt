list(
        APPEND
        SOURCES
        src/Config.cpp
        src/Discovery.cpp
        src/DiscoveryBpf.cpp
        src/DiscoveryBpfLoader.cpp
        src/Session.cpp
)
set(TARGET ebpfdiscovery)

add_library(${TARGET} STATIC ${SOURCES})

target_include_directories(${TARGET} PRIVATE src PUBLIC headers)

target_link_libraries(${TARGET}
        PUBLIC
            bpfload
            ebpfdiscoveryproto
            ebpfdiscoveryshared
            ebpfdiscoveryskel
            httpparser
            logging
            service
            CONAN_PKG::spdlog
            CONAN_PKG::fmt
            CONAN_PKG::boost
)

if (BUILD_TESTS)
    list(APPEND TEST_SOURCES test/LRUCacheTest.cpp)
    set(TEST_TARGET test${TARGET})

    add_executable(${TEST_TARGET} ${TEST_SOURCES})
    target_link_libraries(${TEST_TARGET} CONAN_PKG::gtest ${TARGET})
    target_include_directories(${TEST_TARGET} PRIVATE src)
    gtest_discover_tests(${TEST_TARGET})
endif ()
