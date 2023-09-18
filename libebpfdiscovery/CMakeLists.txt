list(
	APPEND
	SOURCES
	src/Config.cpp
	src/Discovery.cpp
	src/IpUtils.cpp
	src/Log.cpp
	src/Session.cpp
	src/StringFunctions.cpp
)
set(TARGET ebpfdiscovery)

add_library(${TARGET} STATIC ${SOURCES})

target_include_directories(${TARGET} PRIVATE src PUBLIC headers /home/sten/.conan/data/elfutils/0.182.20220704-091150/ci/stable/package/849fae388172c7f2ee94c3a40101d1388f490a52/include /home/sten/.conan/data/gsl/2.0.0.20220628-132757/ci/stable/package/67a7e4f791f896d5af818c657f6da6304cdfff51/include )

target_link_libraries(${TARGET} bpfload)
target_link_libraries(${TARGET} ebpfdiscoveryshared)
target_link_libraries(${TARGET} ebpfdiscoveryskel)
target_link_libraries(${TARGET} fmt::fmt)
target_link_libraries(${TARGET} httpparser)
target_link_libraries(${TARGET} ebpfdiscoveryproto)

if(BUILD_TESTS)
	list(APPEND TEST_SOURCES test/StringFunctionsTest.cpp test/LRUCacheTest.cpp test/IpUtilsTest.cpp)
	set(TEST_TARGET test${TARGET})

	add_executable(${TEST_TARGET} ${TEST_SOURCES})
	target_link_libraries(${TEST_TARGET} GTest::gtest_main ${TARGET})
	target_include_directories(${TEST_TARGET} PRIVATE src)
	gtest_discover_tests(${TEST_TARGET})
endif()
