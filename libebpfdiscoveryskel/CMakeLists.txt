set(BPF_C_FLAGS ${BPF_C_FLAGS} -I${PROJECT_SOURCE_DIR}/libebpfdiscoveryshared/headers)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(BpfObject REQUIRED)
bpf_object(ebpfdiscoveryskel src/discovery.bpf.c)
