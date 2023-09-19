cmake_minimum_required(VERSION 3.16)

option(BUILD_TESTS "Build tests" ON)
set(THIRDPARTY_MAKE_JOBS_COUNT "1" CACHE STRING "Number of jobs to use when compiling thirdparty submodules")
set(_project_name "ebpf-discovery")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
# set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
	set(ARCH "x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
	set(ARCH "arm")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
	set(ARCH "arm64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le")
	set(ARCH "powerpc")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
	set(ARCH "mips")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "riscv64")
	set(ARCH "riscv")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
	set(ARCH "loongarch")
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
	set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

file(READ "version.properties" ver)
string(REGEX MATCH "version=([0-9]+)\.([0-9]+)\.([0-9]+)" _ ${ver})
if(NOT CMAKE_MATCH_COUNT EQUAL 3)
	message(FATAL_ERROR "Version parsing failed\n    Got: ${ver}")
endif()

set(EBPFDISCOVERY_VERSION_MAJOR ${CMAKE_MATCH_1})
set(EBPFDISCOVERY_VERSION_MINOR ${CMAKE_MATCH_2})
set(EBPFDISCOVERY_VERSION_PATCH ${CMAKE_MATCH_3})
add_definitions(-DEBPFDISCOVERY_VERSION_MAJOR=${EBPFDISCOVERY_VERSION_MAJOR})
add_definitions(-DEBPFDISCOVERY_VERSION_MINOR=${EBPFDISCOVERY_VERSION_MINOR})
add_definitions(-DEBPFDISCOVERY_VERSION_PATCH=${EBPFDISCOVERY_VERSION_PATCH})

project(
	${_project_name} VERSION "${EBPFDISCOVERY_VERSION_MAJOR}.${EBPFDISCOVERY_VERSION_MINOR}.${EBPFDISCOVERY_VERSION_PATCH}" LANGUAGES C CXX
)

set(BPF_C_FLAGS ${BPF_C_FLAGS} -DTARGET_BPF)

# Set DEBUG macro in debug build
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(BPF_C_FLAGS ${BPF_C_FLAGS} -DDEBUG)
endif()

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED COMPONENTS program_options)
if(Boost_FOUND)
	include_directories(${Boost_INCLUDE_DIRS})
endif()

if(NOT TARGET fmt)
	find_package(fmt 8.0.1 REQUIRED)
endif(NOT TARGET fmt)

if(BUILD_TESTS)
	include(FetchContent)
	FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip)
	FetchContent_MakeAvailable(googletest)

	include(CTest)
	include(GoogleTest)
	enable_testing()
	add_custom_target(run-tests COMMAND ${CMAKE_CTEST_COMMAND} -T Test --no-compress-output --output-on-failure USES_TERMINAL)
endif()

add_subdirectory(thirdparty)
execute_process(
	COMMAND ${CMAKE_COMMAND} -DTHIRDPARTY_MAKE_JOBS_COUNT=${THIRDPARTY_MAKE_JOBS_COUNT} ${PROJECT_SOURCE_DIR}/thirdparty
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/thirdparty
)
execute_process(COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/thirdparty)

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_BINARY_DIR}/thirdparty/bpftool/bootstrap/bpftool)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/thirdparty/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_BINARY_DIR}/thirdparty/libbpf/libbpf.a)

add_subdirectory(libbpfload)
add_subdirectory(libebpfdiscoveryproto)
add_subdirectory(libebpfdiscovery)
add_subdirectory(libebpfdiscoveryshared)
add_subdirectory(libebpfdiscoveryskel)
add_subdirectory(libhttpparser)

add_subdirectory(ebpfdiscoverysrv)
