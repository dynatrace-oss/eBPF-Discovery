list(
	APPEND
	SOURCES
	src/btf_helpers.c
	src/trace_helpers.c
	src/uprobe_helpers.c
)
set(TARGET bpfload)

add_library(${TARGET} STATIC ${SOURCES})
target_include_directories(${TARGET} PRIVATE src headers/bpfload PUBLIC headers)
target_include_directories(${TARGET} PRIVATE ${LIBBPF_INCLUDE_DIRS})
