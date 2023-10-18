list(APPEND SOURCES src/Logger.cpp)
set(TARGET logging)

add_library(${TARGET} STATIC ${SOURCES})
target_include_directories(${TARGET} PRIVATE src PUBLIC headers)
target_link_libraries(${TARGET} spdlog::spdlog)
