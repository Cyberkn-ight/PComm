cmake_minimum_required(VERSION 3.16)
project(PComm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(pcomm
    src/main.c
    src/config.c
    src/base32.c
    src/identity.c
    src/crypto.c
    src/bencode.c
    src/dht.c
    src/cell.c
    src/circuit.c
    src/db.c
    src/net.c
    src/proto.c
    src/onion.c
    src/msg.c
    src/receive.c
    src/replay.c
    src/relay.c
    src/sendmsg.c
    src/mesh.c
    src/hidden.c
    src/sb.c
    src/http_util.c
    src/http.c
    src/peers.c
)

target_include_directories(pcomm PRIVATE src)

target_link_libraries(pcomm PRIVATE sqlite3 ssl crypto pthread)

if(WIN32)
    target_link_libraries(pcomm PRIVATE ws2_32)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(test_replay_cache tests/test_replay_cache.c src/replay.c)
    target_include_directories(test_replay_cache PRIVATE src)
    target_link_libraries(test_replay_cache PRIVATE pthread)
    add_test(NAME replay_cache COMMAND test_replay_cache)

    add_executable(test_receive
        tests/test_receive.c
        src/receive.c
        src/replay.c
        src/crypto.c
        src/msg.c
        src/db.c
    )
    target_include_directories(test_receive PRIVATE src)
    target_link_libraries(test_receive PRIVATE sqlite3 crypto pthread)
    if(WIN32)
        target_link_libraries(test_receive PRIVATE ws2_32)
    endif()
    add_test(NAME receive_replay COMMAND test_receive)
endif()

