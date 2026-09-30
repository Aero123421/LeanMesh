# Identity and credentials (S5): credential objects/checks, sealed record payloads, boot loader.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/credentials.cpp
    ${CMAKE_CURRENT_LIST_DIR}/records.cpp
    ${CMAKE_CURRENT_LIST_DIR}/join_wire.cpp
    ${CMAKE_CURRENT_LIST_DIR}/discovery.cpp
    ${CMAKE_CURRENT_LIST_DIR}/proxy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/join.cpp
    ${CMAKE_CURRENT_LIST_DIR}/membership.cpp
    ${CMAKE_CURRENT_LIST_DIR}/membership_join.cpp
    ${CMAKE_CURRENT_LIST_DIR}/membership_ops.cpp
    ${CMAKE_CURRENT_LIST_DIR}/membership_cmd.cpp
    ${CMAKE_CURRENT_LIST_DIR}/lifecycle.cpp)
