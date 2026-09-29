# C ABI (api/leanmesh.h). Slices add their entry points in separate files (capi_<area>.cpp).
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/capi.cpp)
