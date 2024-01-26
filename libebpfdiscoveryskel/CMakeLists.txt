set(TARGET ebpfdiscoveryskel)

set(BPF_C_FLAGS ${BPF_C_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/src -I${PROJECT_SOURCE_DIR}/libebpfdiscoveryshared/headers)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

get_target_property(LIBBPF_LIBRARIES libbpf IMPORTED_LOCATION)
get_target_property(LIBBPF_INCLUDE_DIRS libbpf INTERFACE_INCLUDE_DIRECTORIES)
get_target_property(BPFOBJECT_BPFTOOL_EXE bpftool IMPORTED_LOCATION)
find_package(BpfObject REQUIRED)
bpf_object(${TARGET} src/discovery.bpf.c)

if(BUILD_BPF_TESTS)
	set(TEST_SKEL_TARGET ebpfdiscoverytestskel)
	set(BPF_C_FLAGS ${BPF_C_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/test)
	bpf_object(${TEST_SKEL_TARGET} testbpf/discoveryTest.bpf.c)

	list(APPEND TEST_SOURCES test/DataFunctionsTest.cpp)
	set(TEST_TARGET test${TARGET})

	add_executable(${TEST_TARGET} ${TEST_SOURCES})
	target_link_libraries(${TEST_TARGET} CONAN_PKG::gtest ${TEST_SKEL_TARGET})
	gtest_discover_tests(${TEST_TARGET})
endif()
