# Root-only modules (root builds). Route topology first (ROUTE-MODEL slice).
list(APPEND LM_ROOT_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/topology.cpp
    ${CMAKE_CURRENT_LIST_DIR}/routes.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ledger.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ledger_join.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ledger_ops.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ledger_backup.cpp
    ${CMAKE_CURRENT_LIST_DIR}/backup.cpp
    ${CMAKE_CURRENT_LIST_DIR}/lifecycle.cpp
    ${CMAKE_CURRENT_LIST_DIR}/channel_coordinator.cpp
    ${CMAKE_CURRENT_LIST_DIR}/groups.cpp)
