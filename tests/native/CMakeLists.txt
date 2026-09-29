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
lm_add_test(test_runtime_radio SOURCES test_runtime_radio.cpp LABELS "integration;sim;scenario")
lm_add_test(test_store SOURCES test_store.cpp LABELS "integration;store;scenario")
lm_add_test(test_runtime_meshsim SOURCES test_runtime_meshsim.cpp LABELS "integration;sim;meshsim")
target_compile_definitions(test_runtime_meshsim PRIVATE MESHSIM_EXE="$<TARGET_FILE:meshsim>")
add_dependencies(test_runtime_meshsim meshsim)
lm_add_test(test_wire SOURCES test_wire.cpp LABELS "unit;wire;scenario")
# CRYPTO slice: record layer, identity/COSE, EDHOC suite-3 handshake; the RFC 9529 replay is C. The
# linker wraps the allocator so the test can measure PSA heap use (peak and leaks).
lm_add_test(test_security SOURCES test_security.cpp edhoc_rfc9529.c LABELS "unit;integration;crypto;scenario")
target_include_directories(test_security PRIVATE
    "${LM_REPO_ROOT}/third_party/libedhoc/tests/host/rfc9529/support")
if(NOT LM_SANITIZE)
    target_compile_definitions(test_security PRIVATE LM_TEST_HEAP_WRAP=1)
    target_link_options(test_security PRIVATE
        -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free)
endif()
