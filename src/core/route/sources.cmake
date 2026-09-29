# Route model (ROUTE-MODEL slice): forwarding checks, integer link score, bounded path cache.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/forward.cpp
    ${CMAKE_CURRENT_LIST_DIR}/score.cpp
    ${CMAKE_CURRENT_LIST_DIR}/path_cache.cpp
    ${CMAKE_CURRENT_LIST_DIR}/mesh_wire.cpp
    ${CMAKE_CURRENT_LIST_DIR}/mesh.cpp)
