# ESP-IDF ports (firmware only). Chip #ifdefs are allowed only in this directory (AGENTS.md).
list(APPEND LM_PORT_IDF_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/assert_idf.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_clock.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_health.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_jobs.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_ota.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_owner.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_pm.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_platform.cpp
    ${CMAKE_CURRENT_LIST_DIR}/idf_radio.cpp)
# STORE slice: NVS + raw journal partition.
list(APPEND LM_PORT_IDF_SOURCES ${CMAKE_CURRENT_LIST_DIR}/idf_store.cpp)
