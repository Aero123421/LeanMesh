# Channel plan participant, clock, recovery scan and survey visit (S17). I/O-free; compiled for every role.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/wire.cpp
    ${CMAKE_CURRENT_LIST_DIR}/channel.cpp)
