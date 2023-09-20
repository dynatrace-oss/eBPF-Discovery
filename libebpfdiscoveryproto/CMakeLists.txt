set(PROTO_DIR_NAME proto)

list(
	APPEND
	PROTO_SOURCES
	${PROTO_DIR_NAME}/ebpfdiscoveryproto/example.proto
)

set(TARGET ebpfdiscoveryproto)

include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SOURCES})

add_library(${TARGET} STATIC ${PROTO_SRCS})
target_link_libraries(${TARGET} protobuf::libprotobuf)
target_include_directories(${TARGET} PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_DIR_NAME})