# Simulation ports + world (meshsim and native integration tests only; never in firmware).
list(APPEND LM_PORT_SIM_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/assert_sim.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sim_node.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sim_pm.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sim_ports.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sim_provision.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sim_store.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sim_world.cpp)
