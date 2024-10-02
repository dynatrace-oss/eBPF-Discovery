# Copyright 2024 Dynatrace LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

set(TARGET ebpfdiscoveryskel)

set(BPF_C_FLAGS ${BPF_C_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/src -I${PROJECT_SOURCE_DIR}/libebpfdiscoveryshared/headers)

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
