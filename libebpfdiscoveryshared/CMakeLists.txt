set(TARGET ebpfdiscoveryshared)

add_library(${TARGET} INTERFACE)
target_include_directories(${TARGET} INTERFACE headers)
