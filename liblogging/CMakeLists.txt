list(APPEND SOURCES src/Logger.cpp src/Formatting.cpp)
set(TARGET logging)

add_library(${TARGET} STATIC ${SOURCES})
target_include_directories(${TARGET} PRIVATE src PUBLIC headers)

target_link_libraries(${TARGET} CONAN_PKG::spdlog CONAN_PKG::boost)

if(BUILD_TESTS)
	list(APPEND TEST_SOURCES test/FormattingTest.cpp)
	set(TEST_TARGET test${TARGET})

	add_executable(${TEST_TARGET} ${TEST_SOURCES})
	target_link_libraries(${TEST_TARGET} CONAN_PKG::gtest CONAN_PKG::boost ${TARGET})
	target_include_directories(${TEST_TARGET} PRIVATE src)
	gtest_discover_tests(${TEST_TARGET})
endif()
