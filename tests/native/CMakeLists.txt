# Native tests. One executable per area; each registers one CTest entry with labels.
# Label "scenario" marks binaries containing tests named after tests/scenarios.json IDs.
function(lm_add_test name)
    cmake_parse_arguments(T "" "" "SOURCES;LABELS" ${ARGN})
    # The sim's LM_ASSERT handler in every test: SDK objects (Engine, P8 role accessors) need it whatever order the
    # static libraries are scanned in.
    add_executable(${name} ${T_SOURCES} ${LM_REPO_ROOT}/src/port/sim/assert_sim.cpp)
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(${name} PRIVATE lm_sim)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "${T_LABELS}" TIMEOUT 120)
endfunction()

# Python offline issuer -> SDK verifier/Join. Invoked by host/tests/integration, not an empty CTest.
add_executable(issuer_driver issuer_driver.cpp ${LM_REPO_ROOT}/src/port/sim/assert_sim.cpp)
target_compile_options(issuer_driver PRIVATE ${LM_CXX_WARNINGS})
target_link_libraries(issuer_driver PRIVATE lm_sim)

lm_add_test(test_foundation SOURCES test_foundation.cpp LABELS "unit;scenario")
lm_add_test(test_crypto_backend SOURCES test_crypto_backend.cpp edhoc_link_check.c LABELS "unit;crypto;scenario")
lm_add_test(test_runtime_sim SOURCES test_runtime_sim.cpp LABELS "integration;sim;scenario")
lm_add_test(test_runtime_radio SOURCES test_runtime_radio.cpp LABELS "integration;sim;scenario")
lm_add_test(test_store SOURCES test_store.cpp LABELS "integration;store;scenario")
lm_add_test(test_runtime_meshsim SOURCES test_runtime_meshsim.cpp LABELS "integration;sim;meshsim")
target_compile_definitions(test_runtime_meshsim PRIVATE MESHSIM_EXE="$<TARGET_FILE:meshsim>")
add_dependencies(test_runtime_meshsim meshsim)
lm_add_test(test_wire SOURCES test_wire.cpp LABELS "unit;wire;scenario")
# ARCH2-P2A: byte-exact golden encodings of the compact fixed-layout records (one field list per record).
lm_add_test(test_codec SOURCES test_codec.cpp LABELS "unit;wire")
lm_add_test(test_route SOURCES test_route.cpp LABELS "unit;integration;route;scenario")
# CRYPTO slice: record layer, identity/COSE, EDHOC suite-3 handshake; the RFC 9529 replay is C. The
# linker wraps the allocator so the test can measure PSA heap use (peak and leaks).
# GNU ld --wrap and glibc malloc_usable_size have no macOS equivalent: the test runs on Linux (CI) only.
if(APPLE)
    message(STATUS "test_security skipped: it needs GNU ld --wrap (Linux only)")
else()
lm_add_test(test_security SOURCES test_security.cpp edhoc_rfc9529.c LABELS "unit;integration;crypto;scenario")
target_include_directories(test_security PRIVATE
    "${LM_REPO_ROOT}/third_party/libedhoc/tests/host/rfc9529/support")
# Fault injection (FIX1): psa_destroy_key / psa_hash_update failures are injected through the wrap.
target_link_options(test_security PRIVATE -Wl,--wrap=psa_destroy_key -Wl,--wrap=psa_hash_update)
if(NOT LM_SANITIZE)
    target_compile_definitions(test_security PRIVATE LM_TEST_HEAP_WRAP=1)
    target_link_options(test_security PRIVATE
        -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free)
endif()
endif()
# IDENTITY+LINK slice (S5): credential codecs/checks and link sessions between provisioned sim nodes.
# The fleet issuer lm_fleet is TEST-ONLY (tools/lmfleet); nothing here reaches firmware.
lm_add_test(test_link SOURCES test_link.cpp LABELS "integration;sim;link;scenario")
target_link_libraries(test_link PRIVATE lm_fleet)
lm_add_test(test_credentials SOURCES test_credentials.cpp LABELS "unit;link;scenario")
target_link_libraries(test_credentials PRIVATE lm_fleet)
# USB-SERIAL slice (S10): the real root adapter against the Host's native helper (host_usb.cpp is compiled
# into the test: same sources as libleanmesh_host).
lm_add_test(test_serial SOURCES test_serial.cpp ${LM_REPO_ROOT}/src/hostnative/host_usb.cpp LABELS "integration;sim;serial;scenario")
target_link_libraries(test_serial PRIVATE lm_fleet)
# DELIVERY slice (S9): end sessions, E2E records, receipts, dedup, deadlines, journal (sim network).
lm_add_test(test_delivery SOURCES test_delivery.cpp LABELS "integration;sim;delivery;scenario")
target_link_libraries(test_delivery PRIVATE lm_fleet)
# JOIN slice (S8): Join/resume/leave over the simulated medium, power-cut sweep over every join record commit.
lm_add_test(test_join SOURCES test_join.cpp LABELS "integration;sim;join;scenario")
target_link_libraries(test_join PRIVATE lm_fleet)
# FRAGMENT slice (S12): FRAGMENT / TRANSFER_BITMAP, reassembly slots, control objects, the 4 KiB object.
lm_add_test(test_fragment SOURCES test_fragment.cpp LABELS "integration;sim;delivery;scenario")
target_link_libraries(test_fragment PRIVATE lm_fleet)
# SCHED slice (S14): DRR / control reserve / airtime bucket decisions, TX-pool admission, owner under a join storm.
lm_add_test(test_sched SOURCES test_sched.cpp LABELS "integration;sim;sched;scenario")
target_link_libraries(test_sched PRIVATE lm_fleet)
# MESH slice (S11): formation, registration, leases, repair, queries and delivery over the formed mesh.
lm_add_test(test_mesh SOURCES test_mesh.cpp LABELS "integration;sim;mesh;scenario")
target_link_libraries(test_mesh PRIVATE lm_fleet)
target_sources(test_mesh PRIVATE ${LM_REPO_ROOT}/firmware/common/bench_console/bench_recovery.c)
target_include_directories(test_mesh PRIVATE ${LM_REPO_ROOT}/firmware/common/bench_console/include)
set_tests_properties(test_mesh PROPERTIES TIMEOUT 900) # 21..41 node formations: minutes under ASan/UBSan
# GROUP slice (S15): GroupSnapshotV2 pages, fan-out from the origin, per-target results, cancel, fixed set.
lm_add_test(test_group SOURCES test_group.cpp LABELS "integration;sim;group;scenario")
target_link_libraries(test_group PRIVATE lm_fleet)
# POWER slice (S16): three power modes, poll/grant, parent mailbox, episodes and budgets, sleep ticket race, session
# retention, the root's schedule view. Sim time only: no energy, no current.
lm_add_test(test_power SOURCES test_power.cpp LABELS "integration;sim;power;scenario")
target_link_libraries(test_power PRIVATE lm_fleet)
target_compile_definitions(test_power PRIVATE LM_POWER_GOLDEN="${LM_REPO_ROOT}/tests/power_golden.json")
# CHANNEL slice (S17): time bounds, survey, PREPARE / COMMIT / recovery, freeze, rollback, persisted states.
lm_add_test(test_channel SOURCES test_channel.cpp LABELS "integration;sim;channel;scenario")
target_link_libraries(test_channel PRIVATE lm_fleet)
# DIAG slice (S19): diagnostics snapshot with validity bits, capability rows, no polling.
lm_add_test(test_diag SOURCES test_diag.cpp LABELS "integration;sim;diag;scenario")
# OTA software part (S19): manifest check, rollback state, boot decisions, state-record power-cut sweep (sim).
lm_add_test(test_ota SOURCES test_ota.cpp LABELS "unit;integration;store;ota;scenario")
target_link_libraries(test_ota PRIVATE lm_fleet)
# LIFECYCLE slice (S18): lease renewal, revocation, transfer, commissioning window, root handover (sim, hours of
# virtual time: the soak runs longer than the default timeout).
lm_add_test(test_lifecycle SOURCES test_lifecycle.cpp LABELS "integration;sim;lifecycle;scenario")
target_link_libraries(test_lifecycle PRIVATE lm_fleet)
set_tests_properties(test_lifecycle PROPERTIES TIMEOUT 900)
# MODEL (S20): seeded random schedules against the production delivery/link/journal code (seed + event log + minimal
# counterexample on failure, docs/18 §2). LM_MODEL_SEEDS / LM_MODEL_SEED select the runs.
lm_add_test(test_model SOURCES test_model.cpp LABELS "integration;sim;model;scenario")
target_link_libraries(test_model PRIVATE lm_fleet)
set_tests_properties(test_model PROPERTIES TIMEOUT 900)
execute_process(COMMAND git -C "${LM_REPO_ROOT}" rev-parse --short HEAD OUTPUT_VARIABLE LM_MODEL_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
target_compile_definitions(test_model PRIVATE LM_MODEL_COMMIT="${LM_MODEL_COMMIT}")
# ROOT TERM (ARCH2): one root_term per root boot, members follow it, nothing of the old clock is read on the new one.
lm_add_test(test_term SOURCES test_term.cpp LABELS "integration;sim;mesh;lifecycle;scenario")
target_link_libraries(test_term PRIVATE lm_fleet)
set_tests_properties(test_term PROPERTIES TIMEOUT 900)
# FIELD test kit (firmware/field_node): the node's wire formats, join backoff, panel frame and the bench console's line assembly are plain C without ESP-IDF
# (docs/field/protocol.md); the firmware around them needs a board.
set(LM_FIELD_NODE_MAIN ${LM_REPO_ROOT}/firmware/field_node/main)
set(LM_BENCH_CONSOLE ${LM_REPO_ROOT}/firmware/common/bench_console)
lm_add_test(test_field SOURCES test_field.cpp ${LM_FIELD_NODE_MAIN}/field_proto.c ${LM_FIELD_NODE_MAIN}/field_render.c
            ${LM_BENCH_CONSOLE}/bench_line.c LABELS "unit;field")
target_include_directories(test_field PRIVATE ${LM_FIELD_NODE_MAIN} ${LM_BENCH_CONSOLE}/include)
target_sources(test_field PRIVATE ${LM_BENCH_CONSOLE}/bench_recovery.c)
# Sim-heavy suites that take over 120 s under ASan/UBSan on a CI runner (they finish in seconds otherwise).
set_tests_properties(test_power test_channel test_group test_delivery PROPERTIES TIMEOUT 900)
