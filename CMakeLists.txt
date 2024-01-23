cmake_minimum_required(VERSION 3.22.3)

option(BUILD_TESTS "Build tests" ON)
set(THIRDPARTY_MAKE_JOBS_COUNT "1" CACHE STRING "Number of jobs to use when compiling thirdparty submodules")
set(_project_name "ebpf-discovery")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
# set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment
if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
    set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
    set(ARCH "arm")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
    set(ARCH "arm64")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le")
    set(ARCH "powerpc")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
    set(ARCH "mips")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "riscv64")
    set(ARCH "riscv")
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
    set(ARCH "loongarch")
endif ()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

if ("${PROJECT_VERSION}" STREQUAL "")
    message(FATAL_ERROR "Project version has not been provided\n    Please, provide project version using -DPROJECT_VERSION")
endif ()

string(REGEX MATCH "([0-9]+)\.([0-9]+)\.([0-9]+)" _ "${PROJECT_VERSION}")
if (NOT CMAKE_MATCH_COUNT EQUAL 3)
    message(FATAL_ERROR "Incorrect project version number format: ${PROJECT_VERSION}. Please provide the project version number in the format major.minor.patch")
endif ()

project(
        ${_project_name} VERSION "${PROJECT_VERSION}" LANGUAGES C CXX
)

set(BPF_C_FLAGS ${BPF_C_FLAGS} -DTARGET_BPF)

# Set DEBUG macro in debug build and add additional warnings
set(EXTRA_DEBUG_FLAGS -DDEBUG -Wall -Wextra -Wno-unused-parameter -Wno-unused-value -Wno-missing-field-initializers)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(${EXTRA_DEBUG_FLAGS})
    set(BPF_C_FLAGS ${BPF_C_FLAGS} ${EXTRA_DEBUG_FLAGS})
endif ()

if (CONAN_EXPORTED)
	include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
	conan_basic_setup(TARGETS)
else ()
	include(conan.cmake)
	conan_cmake_run(CONANFILE conanfile.txt
			BASIC_SETUP CMAKE_TARGETS UPDATE NO_OUTPUT_DIRS
			BUILD missing
	)
endif ()

function (collect_licenses conanfile)
    file(READ ${conanfile} conanfile_contents)
    string(REGEX MATCH "\\[requires\\](.*)" requires_section ${conanfile_contents})
    string(REPLACE ";" "\n" requires_section ${CMAKE_MATCH_1})
    string(REGEX MATCHALL "([^\n]+)" requirements_list ${requires_section})
    foreach(requirement IN LISTS requirements_list)
        string(REGEX MATCHALL "(.*)\/(.*)" requirement_match ${requirement})
        if (NOT requirement_match)
            break()
        endif ()
        set(requirement_name ${CMAKE_MATCH_1})
        set(requirement_version ${CMAKE_MATCH_2})
        string(TOUPPER ${requirement_name} requirement_name_uppercase)
        set(requirement_license_dir "${CONAN_${requirement_name_uppercase}_ROOT}/licenses")
        file(GLOB requirement_licenses "${requirement_license_dir}/*")
        if (requirement_licenses)
            message(STATUS "License file for ${requirement} found ${requirement_licenses}")
        else ()
            message(FATAL_ERROR "Cannot find any license files in ${requirement_license_dir}")
        endif ()
        file(COPY ${requirement_licenses} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/licenses/${requirement}/")
    endforeach()
endfunction()

collect_licenses(conanfile.txt)

set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of googletest" FORCE)

if (BUILD_TESTS OR BUILD_BPF_TESTS)
    include(CTest)
    include(GoogleTest)
    enable_testing()

    add_custom_target(run-tests COMMAND ${CMAKE_CTEST_COMMAND} -T Test --no-compress-output --output-on-failure USES_TERMINAL)
endif ()

add_subdirectory(third_party)
execute_process(
        COMMAND ${CMAKE_COMMAND} -DTHIRDPARTY_MAKE_JOBS_COUNT=${THIRDPARTY_MAKE_JOBS_COUNT} ${PROJECT_SOURCE_DIR}/third_party
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/third_party
)
execute_process(COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/third_party)

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_BINARY_DIR}/third_party/bpftool/bootstrap/bpftool)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/third_party/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_BINARY_DIR}/third_party/libbpf/libbpf.a)

add_subdirectory(libbpfload)
add_subdirectory(libebpfdiscovery)
add_subdirectory(libebpfdiscoveryproto)
add_subdirectory(libebpfdiscoveryshared)
add_subdirectory(libebpfdiscoveryskel)
add_subdirectory(libhttpparser)
add_subdirectory(libservice)
add_subdirectory(liblogging)

include(GNUInstallDirs)
add_subdirectory(ebpfdiscoverysrv)
install(TARGETS ebpfdiscoverysrv ebpfdiscoverysrv DESTINATION ${CMAKE_INSTALL_BINDIR})