# Power (S16): three power modes in one engine, sleep tickets, poll/grant, parent mailbox, root's view.
# I/O-free; compiled for every role (the child and member tables are sized to zero where the role cannot exist).
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/policy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/power_wire.cpp
    ${CMAKE_CURRENT_LIST_DIR}/power.cpp
    ${CMAKE_CURRENT_LIST_DIR}/power_link.cpp
    ${CMAKE_CURRENT_LIST_DIR}/power_root.cpp
    ${CMAKE_CURRENT_LIST_DIR}/delivery_power.cpp
    ${CMAKE_CURRENT_LIST_DIR}/engine_power.cpp)
