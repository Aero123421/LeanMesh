# ESP-IDF ports (firmware only). Chip #ifdefs are allowed only in this directory (AGENTS.md).
list(APPEND LM_PORT_IDF_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/assert_idf.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_clock.cpp)
