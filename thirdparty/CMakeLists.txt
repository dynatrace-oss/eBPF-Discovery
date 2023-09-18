cmake_minimum_required(VERSION 3.22)
project(thirdparty)
set(THIRDPARTY_MAKE_JOBS_COUNT "1" CACHE STRING "Number of jobs to use when compiling thirdparty submodules")

include(ExternalProject)
find_package(Git REQUIRED)

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src/Makefile OR NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/libbpf/src/Makefile)
	execute_process(
		COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive -- bpftool
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} COMMAND_ERROR_IS_FATAL ANY
	)
endif()
ExternalProject_Add(
	bpftool
	PREFIX bpftool
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
	CONFIGURE_COMMAND ""
	BUILD_COMMAND make -j${THIRDPARTY_MAKE_JOBS_COUNT} bootstrap OUTPUT=${CMAKE_BINARY_DIR}/bpftool/
	BUILD_IN_SOURCE TRUE
	INSTALL_COMMAND ""
	STEP_TARGETS build
)
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src/Makefile)
	execute_process(
		COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive -- libbpf
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} COMMAND_ERROR_IS_FATAL ANY
	)
endif()
ExternalProject_Add(
	libbpf
	PREFIX libbpf
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
	CONFIGURE_COMMAND ""
	BUILD_COMMAND
		make -j${THIRDPARTY_MAKE_JOBS_COUNT} BUILD_STATIC_ONLY=1 OBJDIR=${CMAKE_BINARY_DIR}/libbpf/libbpf DESTDIR=${CMAKE_BINARY_DIR}/libbpf
		INCLUDEDIR= LIBDIR= UAPIDIR= install install_uapi_headers
	BUILD_IN_SOURCE TRUE
	INSTALL_COMMAND ""
	STEP_TARGETS build
)
