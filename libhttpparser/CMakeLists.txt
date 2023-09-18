list(APPEND SOURCES src/HttpRequestParser.cpp)
set(TARGET httpparser)

add_library(${TARGET} STATIC ${SOURCES})
target_include_directories(${TARGET} PRIVATE src PUBLIC headers)

target_link_libraries(${TARGET} ebpfdiscoveryshared)

if(BUILD_TESTS)
	list(APPEND TEST_SOURCES test/HttpRequestParserTest.cpp)
	set(TEST_TARGET test${TARGET})

	add_executable(${TEST_TARGET} ${TEST_SOURCES})
	target_link_libraries(${TEST_TARGET} GTest::gtest_main ${TARGET})
	target_include_directories(${TEST_TARGET} PRIVATE src)
	gtest_discover_tests(${TEST_TARGET})
endif()
