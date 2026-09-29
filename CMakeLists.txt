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
set(LM_CXX_WARNINGS -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Werror)
add_library(lm_sdk STATIC ${LM_COMMON_SOURCES} ${LM_ROOT_SOURCES})
target_include_directories(lm_sdk PUBLIC "${LM_REPO_ROOT}/api" "${LM_REPO_ROOT}/src" "${LM_GEN_DIR}")
target_compile_definitions(lm_sdk PUBLIC LM_BUILD_PROFILE_SIM)
target_compile_options(lm_sdk PRIVATE ${LM_CXX_WARNINGS} $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions -fno-rtti>)
target_link_libraries(lm_sdk PUBLIC lm_psa lm_edhoc)

# ---- simulation ports (native only) ----
add_library(lm_sim STATIC ${LM_PORT_SIM_SOURCES})
target_compile_options(lm_sim PRIVATE ${LM_CXX_WARNINGS} -fno-exceptions -fno-rtti)
target_link_libraries(lm_sim PUBLIC lm_sdk)

add_executable(meshsim tools/meshsim/main.cpp tools/meshsim/control.cpp tools/meshsim/pty.cpp)
target_compile_options(meshsim PRIVATE ${LM_CXX_WARNINGS})
target_link_libraries(meshsim PRIVATE lm_sim)

if(LM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests/native)
endif()
