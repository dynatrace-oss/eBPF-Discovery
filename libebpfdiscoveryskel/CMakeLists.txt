set(TARGET ebpfdiscoveryskel)

set(BPF_C_FLAGS ${BPF_C_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/src -I${PROJECT_SOURCE_DIR}/libebpfdiscoveryshared/headers)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(BpfObject REQUIRED)
bpf_object(${TARGET} src/discovery.bpf.c)

if(BUILD_BPF_TESTS)
	set(TEST_SKEL_TARGET ebpfdiscoverytestskel)
	bpf_object(${TEST_SKEL_TARGET} bpftest/discoveryTest.bpf.c)

	list(APPEND TEST_SOURCES bpftest/DataFunctionsTest.cpp)
	set(TEST_TARGET test${TARGET})

	add_executable(${TEST_TARGET} ${TEST_SOURCES})
	target_link_libraries(${TEST_TARGET} GTest::gtest_main ${TEST_SKEL_TARGET})
	gtest_discover_tests(${TEST_TARGET})
endif()
