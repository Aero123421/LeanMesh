# Identity and credentials (S5): credential objects/checks, sealed record payloads, boot loader.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/credentials.cpp
    ${CMAKE_CURRENT_LIST_DIR}/records.cpp)
