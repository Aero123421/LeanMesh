# Durable state over the Store port (STORE slice): sealed 2-slot records, boot incarnation, journal.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/journal.cpp
    ${CMAKE_CURRENT_LIST_DIR}/record.cpp)
