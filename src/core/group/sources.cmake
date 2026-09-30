# Group fan-out (S15): snapshot pages, per-target dispatch and results. I/O-free; compiled for every role.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/group.cpp
    ${CMAKE_CURRENT_LIST_DIR}/snapshot.cpp)
