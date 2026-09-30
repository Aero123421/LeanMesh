# Optional OTA, software part (S19). The file is always listed; its body exists only with LM_OTA (Kconfig LEANMESH_OTA).
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/ota.cpp)
