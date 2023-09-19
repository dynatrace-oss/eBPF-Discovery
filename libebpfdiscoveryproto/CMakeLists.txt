list(
	APPEND
	PROTO_SOURCES
	proto/dummy.proto
)

set(TARGET ebpfdiscoveryproto)

find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SOURCES})

add_library(${TARGET} STATIC ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(${TARGET} protobuf::libprotobuf)
target_link_libraries(${TARGET} protobuf::libprotoc)
target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} PUBLIC ${CMAKE_CURRENT_BINARY_DIR})