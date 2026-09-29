# Link layer (S5): neighbour/session table, frame seal/open, the link exchange, RX/TX glue.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/neighbors.cpp
    ${CMAKE_CURRENT_LIST_DIR}/seal.cpp
    ${CMAKE_CURRENT_LIST_DIR}/exchange.cpp
    ${CMAKE_CURRENT_LIST_DIR}/exchange_io.cpp
    ${CMAKE_CURRENT_LIST_DIR}/link_layer.cpp)
