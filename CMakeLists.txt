# Native build: the same core/security sources as the firmware, on simulation ports.
# Produces the meshsim simulator, native tests (CTest) and, later, the host native binding.
#   cmake -S . -B ~/.cache/leanmesh/native -G Ninja && cmake --build ~/.cache/leanmesh/native
#   ctest --test-dir ~/.cache/leanmesh/native --output-on-failure
# Keep build directories outside the repository (scripts/check_spec.py scans *.json/*.md).
# Requires the pinned ESP-IDF tree (for TF-PSA-Crypto sources): -DLM_IDF_PATH=... or $IDF_PATH.
cmake_minimum_required(VERSION 3.25)
project(leanmesh LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(LM_SANITIZE "Build native code with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(LM_BUILD_TESTS "Build native tests" ON)
if(DEFINED ENV{IDF_PATH})
    set(lm_default_idf "$ENV{IDF_PATH}")
else()
    set(lm_default_idf "$ENV{HOME}/esp/esp-idf-v6.0.3")
endif()
set(LM_IDF_PATH "${lm_default_idf}" CACHE PATH "Pinned ESP-IDF checkout (source of TF-PSA-Crypto)")

include(cmake/lm_pins.cmake)
include(cmake/lm_generate.cmake)
include(cmake/lm_crypto_native.cmake)
include(cmake/lm_edhoc.cmake)
include(cmake/lm_sources.cmake)

if(LM_SANITIZE)
    # vptr checks need RTTI, which first-party code does not have (docs/15 §2).
    add_compile_options(-fsanitize=address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined -fno-sanitize=vptr)
endif()

lm_verify_third_party()
lm_add_native_crypto("${LM_IDF_PATH}")

set(LM_GEN_DIR "${CMAKE_BINARY_DIR}/generated")
lm_generate_headers("${LM_GEN_DIR}" ${LM_BUILD_TESTS})
lm_edhoc_collect("${LM_GEN_DIR}/edhoc")

# ---- third-party: libedhoc core + CBOR backend + zcbor (upstream warning set not enforced) ----
add_library(lm_edhoc STATIC ${LM_EDHOC_SOURCES})
target_include_directories(lm_edhoc PUBLIC ${LM_EDHOC_PUBLIC_INCLUDE} PRIVATE ${LM_EDHOC_PRIVATE_INCLUDE})
target_compile_definitions(lm_edhoc PRIVATE ${LM_EDHOC_DEFINITIONS})
target_compile_options(lm_edhoc PRIVATE ${LM_EDHOC_OPTIONS})

# ---- first-party SDK (same sources as the IDF component) ----
set(LM_CXX_WARNINGS -Wall -Wextra -Wshadow $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor> -Werror)
add_library(lm_sdk STATIC ${LM_COMMON_SOURCES} ${LM_ROOT_SOURCES})
target_include_directories(lm_sdk PUBLIC "${LM_REPO_ROOT}/api" "${LM_REPO_ROOT}/src" "${LM_GEN_DIR}")
# The protocol bench carries the optional 4 KiB object lane (docs/09 §6); firmware opts in by Kconfig.
target_compile_definitions(lm_sdk PUBLIC LM_BUILD_PROFILE_SIM LM_OBJECT_TRANSFER=1 LM_OTA=1)
target_compile_options(lm_sdk PRIVATE ${LM_CXX_WARNINGS} $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions -fno-rtti>)
target_link_libraries(lm_sdk PUBLIC lm_psa lm_edhoc)

# ---- simulation ports (native only) ----
add_library(lm_sim STATIC ${LM_PORT_SIM_SOURCES})
target_compile_options(lm_sim PRIVATE ${LM_CXX_WARNINGS} -fno-exceptions -fno-rtti)
target_link_libraries(lm_sim PUBLIC lm_sdk)

# Example applications (docs/17 G6): public C API only. Native tests and meshsim run them; no firmware links them.
add_library(lm_example_apps STATIC examples/apps/equipment_control.c examples/apps/battery_measurement.c)
target_include_directories(lm_example_apps PUBLIC api examples/apps)
target_compile_options(lm_example_apps PRIVATE -Wall -Wextra -Werror)

# One source per line: slices append their cmd_<slice>.cpp here.
add_executable(meshsim
    tools/meshsim/main.cpp
    tools/meshsim/control.cpp
    tools/meshsim/cmd_runtime.cpp
    tools/meshsim/cmd_provision.cpp
    tools/meshsim/cmd_serial.cpp
    tools/meshsim/cmd_join.cpp
    tools/meshsim/cmd_delivery.cpp
    tools/meshsim/cmd_fragment.cpp
    tools/meshsim/cmd_sched.cpp
    tools/meshsim/cmd_group.cpp
    tools/meshsim/cmd_mesh.cpp
    tools/meshsim/cmd_power.cpp
    tools/meshsim/cmd_channel.cpp
    tools/meshsim/cmd_diag.cpp
    tools/meshsim/cmd_lifecycle.cpp
    tools/meshsim/cmd_apps.cpp
    tools/meshsim/topology.cpp
    tools/meshsim/pty.cpp)
target_compile_options(meshsim PRIVATE ${LM_CXX_WARNINGS})
target_link_libraries(meshsim PRIVATE lm_sim lm_fleet lm_example_apps)

# ---- Host native helper (S10): the USB serial session for the Python Host (ctypes) ----
# Same security/serial sources as the firmware; no first-party code is duplicated in Python.
add_library(leanmesh_host SHARED
    src/hostnative/host_usb.cpp
    src/hostnative/lmh_api.cpp
    src/port/sim/assert_sim.cpp)
target_compile_options(leanmesh_host PRIVATE ${LM_CXX_WARNINGS} -fno-exceptions -fno-rtti -fvisibility=hidden)
target_link_libraries(leanmesh_host PRIVATE lm_sdk)
set_target_properties(leanmesh_host PROPERTIES CXX_VISIBILITY_PRESET hidden)

add_subdirectory(tools/lmtool) # codec CLI for differential wire tests
add_subdirectory(tools/lmfleet) # TEST-ONLY fleet issuer (never linked into firmware)
add_subdirectory(tools/budget_probe) # sizeof per profile for scripts/budget_report.py (never linked)

if(LM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests/native)
    # Every function of api/leanmesh.h is defined in this build (nm of lm_sdk + lm_sim); evidence bits match the Host.
    add_test(NAME api_defined COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_api_defined.py --native-build ${CMAKE_BINARY_DIR})
    set_tests_properties(api_defined PROPERTIES LABELS "unit;api" TIMEOUT 60)
endif()
