# C ABI (api/leanmesh.h). Slices add their entry points in separate files (capi_<area>.cpp).
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/capi.cpp
    ${CMAKE_CURRENT_LIST_DIR}/capi_send.cpp
    ${CMAKE_CURRENT_LIST_DIR}/capi_membership.cpp
    ${CMAKE_CURRENT_LIST_DIR}/capi_channel.cpp
    ${CMAKE_CURRENT_LIST_DIR}/capi_group.cpp
    ${CMAKE_CURRENT_LIST_DIR}/capi_power.cpp)
