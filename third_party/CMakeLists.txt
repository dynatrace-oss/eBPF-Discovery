cmake_minimum_required(VERSION 3.22)
project(third_party)
set(THIRDPARTY_MAKE_JOBS_COUNT "1" CACHE STRING "Number of jobs to use when compiling thirdparty submodules")

include(ExternalProject)
find_package(Git REQUIRED)

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src/Makefile OR NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/libbpf/src/Makefile)
	execute_process(
			COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive -- ./bpftool
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} COMMAND_ERROR_IS_FATAL ANY
	)
endif()


# bftool

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bpftool)

execute_process(
		COMMAND make -j${THIRDPARTY_MAKE_JOBS_COUNT} bootstrap OUTPUT=${CMAKE_BINARY_DIR}/bpftool/
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
)

set(TARGET_BPFTOOL bpftool)
add_executable(${TARGET_BPFTOOL} IMPORTED GLOBAL)
set_property(TARGET ${TARGET_BPFTOOL} PROPERTY IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/bpftool/bootstrap/bpftool)
target_compile_options(${TARGET_BPFTOOL} INTERFACE -w)

# libbpf

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/libbpf)

execute_process(
		COMMAND
			make -j${THIRDPARTY_MAKE_JOBS_COUNT} BUILD_STATIC_ONLY=1 OBJDIR=${CMAKE_BINARY_DIR}/libbpf/libbpf DESTDIR=${CMAKE_BINARY_DIR}/libbpf
			INCLUDEDIR= LIBDIR= UAPIDIR= install install_uapi_headers
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/libbpf/src
)

set(TARGET_LIBBPF libbpf)
add_library(${TARGET_LIBBPF} STATIC IMPORTED GLOBAL)
set_property(TARGET ${TARGET_LIBBPF} PROPERTY IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/libbpf/libbpf.a)
target_compile_options(${TARGET_LIBBPF} INTERFACE -w)
target_include_directories(${TARGET_LIBBPF} INTERFACE ${CMAKE_BINARY_DIR}/libbpf)


# bcc/libpf-tools

list(APPEND SOURCES_BCC_LIBBPF_TOOLS
	bcc/libbpf-tools/btf_helpers.c
	bcc/libbpf-tools/trace_helpers.c
	bcc/libbpf-tools/uprobe_helpers.c
)

set(TARGET_BCC_LIBBPF_TOOLS libpf-tools)
add_library(${TARGET_BCC_LIBBPF_TOOLS} STATIC ${SOURCES_BCC_LIBBPF_TOOLS})
target_compile_options(${TARGET_BCC_LIBBPF_TOOLS} INTERFACE -w)
target_include_directories(${TARGET_BCC_LIBBPF_TOOLS} PUBLIC libbpf-tools)
target_link_libraries(${TARGET_BCC_LIBBPF_TOOLS} PRIVATE libbpf)
