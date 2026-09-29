# End-to-end delivery (S9): end sessions (set up by the link exchange in end mode), one-hop
# reliability, receipts, dedup cache, durable journal glue. I/O-free; compiled for every role.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/intent.cpp
    ${CMAKE_CURRENT_LIST_DIR}/end_session.cpp
    ${CMAKE_CURRENT_LIST_DIR}/hop.cpp
    ${CMAKE_CURRENT_LIST_DIR}/fragment.cpp
    ${CMAKE_CURRENT_LIST_DIR}/durable.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery_tx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery_rx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery_sched.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery_durable.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery_host.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery_group.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery_mesh.cpp)
