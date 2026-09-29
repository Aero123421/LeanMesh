# Native tests. One executable per area; each registers one CTest entry with labels.
# Label "scenario" marks binaries containing tests named after tests/scenarios.json IDs.
function(lm_add_test name)
    cmake_parse_arguments(T "" "" "SOURCES;LABELS" ${ARGN})
    add_executable(${name} ${T_SOURCES})
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(${name} PRIVATE lm_sim)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "${T_LABELS}" TIMEOUT 120)
endfunction()

lm_add_test(test_foundation SOURCES test_foundation.cpp LABELS "unit;scenario")
lm_add_test(test_crypto_backend SOURCES test_crypto_backend.cpp edhoc_link_check.c LABELS "unit;crypto;scenario")
lm_add_test(test_runtime_sim SOURCES test_runtime_sim.cpp LABELS "integration;sim;scenario")
