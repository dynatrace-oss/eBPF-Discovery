list(
	APPEND
	PROTO_SOURCES
	ebpfdiscoveryproto/example.proto
)

set(TARGET ebpfdiscoveryproto)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SOURCES})

add_library(${TARGET} STATIC ${PROTO_SRCS})
target_link_libraries(${TARGET} CONAN_PKG::protobuf-c)
target_include_directories(${TARGET} PUBLIC ${CMAKE_CURRENT_BINARY_DIR})