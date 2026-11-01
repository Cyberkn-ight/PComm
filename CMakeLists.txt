cmake_minimum_required(VERSION 3.16)
project(PComm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(pcomm
    src/main.c
    src/config.c
    src/lifecycle.c
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
    src/mailbox.c
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

    add_executable(test_mailbox_guard
        tests/test_mailbox_guard.c src/mailbox.c src/db.c src/replay.c)
    target_include_directories(test_mailbox_guard PRIVATE src)
    target_link_libraries(test_mailbox_guard PRIVATE sqlite3 crypto pthread)

    add_executable(test_mailbox_db tests/test_mailbox_db.c src/db.c src/replay.c)
    target_include_directories(test_mailbox_db PRIVATE src)
    target_link_libraries(test_mailbox_db PRIVATE sqlite3 pthread)

    add_executable(test_proto_limits tests/test_proto_limits.c src/proto.c)
    target_include_directories(test_proto_limits PRIVATE src)
    if(WIN32)
        target_link_libraries(test_mailbox_guard PRIVATE ws2_32)
        target_link_libraries(test_mailbox_db PRIVATE ws2_32)
        target_link_libraries(test_proto_limits PRIVATE ws2_32)
    endif()
    add_test(NAME mailbox_guard COMMAND test_mailbox_guard)
    add_test(NAME mailbox_db COMMAND test_mailbox_db)
    add_test(NAME proto_limits COMMAND test_proto_limits)

    add_executable(test_crypto tests/test_crypto.c src/crypto.c)
    target_include_directories(test_crypto PRIVATE src)
    target_link_libraries(test_crypto PRIVATE crypto)

    add_executable(test_msg tests/test_msg.c src/msg.c)
    target_include_directories(test_msg PRIVATE src)
    if(WIN32)
        target_link_libraries(test_msg PRIVATE ws2_32)
    endif()

    add_executable(test_db tests/test_db.c src/db.c src/replay.c)
    target_include_directories(test_db PRIVATE src)
    target_link_libraries(test_db PRIVATE sqlite3 pthread)
    if(WIN32)
        target_link_libraries(test_db PRIVATE ws2_32)
    endif()

    add_executable(test_bencode tests/test_bencode.c src/bencode.c)
    target_include_directories(test_bencode PRIVATE src)

    add_test(NAME crypto COMMAND test_crypto)
    add_test(NAME msg COMMAND test_msg)
    add_test(NAME db COMMAND test_db)
    add_test(NAME bencode COMMAND test_bencode)

    add_executable(test_lifecycle tests/test_lifecycle.c src/lifecycle.c)
    target_include_directories(test_lifecycle PRIVATE src)
    target_link_libraries(test_lifecycle PRIVATE pthread)
    add_test(NAME lifecycle COMMAND test_lifecycle)
    set_tests_properties(replay_cache receive_replay mailbox_guard mailbox_db proto_limits
        crypto msg db bencode lifecycle PROPERTIES TIMEOUT 30)

    if(UNIX)
        add_executable(test_net_shutdown tests/test_net_shutdown.c src/net.c src/lifecycle.c)
        target_include_directories(test_net_shutdown PRIVATE src)
        target_link_libraries(test_net_shutdown PRIVATE pthread)
        add_test(NAME net_shutdown COMMAND test_net_shutdown)

        get_target_property(PCOMM_SERVICE_SOURCES pcomm SOURCES)
        list(REMOVE_ITEM PCOMM_SERVICE_SOURCES src/main.c)
        add_executable(test_services_shutdown tests/test_services_shutdown.c ${PCOMM_SERVICE_SOURCES})
        target_include_directories(test_services_shutdown PRIVATE src)
        target_link_libraries(test_services_shutdown PRIVATE sqlite3 ssl crypto pthread)
        add_test(NAME services_shutdown COMMAND test_services_shutdown "${CMAKE_CURRENT_SOURCE_DIR}/ui")

        add_executable(test_process_shutdown tests/test_process_shutdown.c)
        target_link_libraries(test_process_shutdown PRIVATE sqlite3)
        add_dependencies(test_process_shutdown pcomm)
        add_test(NAME process_shutdown COMMAND test_process_shutdown
            "$<TARGET_FILE:pcomm>" "${CMAKE_CURRENT_SOURCE_DIR}/ui")
        set_tests_properties(net_shutdown services_shutdown process_shutdown PROPERTIES TIMEOUT 30)
    endif()

    add_custom_target(check
        COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -C "$<CONFIG>"
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        COMMENT "Running PComm core and regression tests"
        VERBATIM
        USES_TERMINAL)
    add_dependencies(check test_replay_cache test_receive test_mailbox_guard test_mailbox_db
        test_proto_limits test_crypto test_msg test_db test_bencode test_lifecycle)
    if(UNIX)
        add_dependencies(check test_net_shutdown test_services_shutdown test_process_shutdown)
    endif()
endif()

