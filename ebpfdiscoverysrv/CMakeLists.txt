list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
set(TARGET ebpfdiscoverysrv)

add_executable(${TARGET} ${SOURCES})

target_link_libraries(${TARGET} PRIVATE ebpfdiscovery)
target_link_options(${TARGET} PRIVATE "-static-libgcc" "-static-libstdc++")
target_compile_definitions(${TARGET} PUBLIC PROJECT_VERSION="${PROJECT_VERSION}")
