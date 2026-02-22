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
    src/db.c
    src/net.c
    src/proto.c
    src/onion.c
    src/msg.c
    src/relay.c
    src/sendmsg.c
    src/sb.c
    src/http_util.c
    src/http.c
    src/peers.c
)

target_include_directories(pcomm PRIVATE src)

target_link_libraries(pcomm PRIVATE sqlite3 ssl crypto pthread)

