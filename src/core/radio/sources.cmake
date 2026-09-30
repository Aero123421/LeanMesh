# Radio-side owner modules: peer registry (16+3+1) and the single-TX manager.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/peer_registry.cpp
    ${CMAKE_CURRENT_LIST_DIR}/tx_manager.cpp)
