# ESP-IDF component wrapper for the LeanMesh SDK. It compiles the same sources as the native build
# (cmake/lm_sources.cmake), the pinned libedhoc and links IDF's `mbedtls` (PSA) component: one
# crypto backend on every target. Use from an app with
#   set(EXTRA_COMPONENT_DIRS <repo>/components)
get_filename_component(LM_COMPONENT_REPO "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

if(CMAKE_BUILD_EARLY_EXPANSION)
    # Requirement scan (script mode): declare dependencies only, generate nothing.
    idf_component_register(PRIV_REQUIRES mbedtls esp_timer esp_system nvs_flash nvs_sec_provider esp_partition esp_wifi
                  esp_event esp_netif freertos esp_driver_usb_serial_jtag esp_pm esp_hw_support app_update
                  bootloader_support)
    return()
endif()

include("${LM_COMPONENT_REPO}/cmake/lm_pins.cmake")
include("${LM_COMPONENT_REPO}/cmake/lm_generate.cmake")
include("${LM_COMPONENT_REPO}/cmake/lm_edhoc.cmake")
include("${LM_COMPONENT_REPO}/cmake/lm_sources.cmake")

lm_verify_third_party()
set(lm_gen "${CMAKE_CURRENT_BINARY_DIR}/lm_generated")
lm_generate_headers("${lm_gen}" FALSE)
lm_edhoc_collect("${lm_gen}/edhoc")

if(CONFIG_LEANMESH_PROFILE_ROOT)
    set(lm_profile ROOT)
    set(lm_role_sources ${LM_ROOT_SOURCES} ${LM_ROOT_IDF_SOURCES}) # S10: + USB-Serial/JTAG transport
elseif(CONFIG_LEANMESH_PROFILE_RELAY)
    set(lm_profile RELAY)
    set(lm_role_sources "")
else()
    set(lm_profile LEAF)
    set(lm_role_sources "")
endif()

# Bench/HIL provisioning (leanmesh_bench.h): only when the build asks for it; never in the SDK source lists.
set(lm_bench_sources "")
set(lm_bench_include "")
if(CONFIG_LEANMESH_BENCH_PROVISIONING)
    set(lm_bench_sources "${LM_COMPONENT_REPO}/src/port/idf/idf_bench.cpp")
    set(lm_bench_include "${CMAKE_CURRENT_LIST_DIR}/bench")
endif()

idf_component_register(
    SRCS ${LM_COMMON_SOURCES} ${lm_role_sources} ${LM_PORT_IDF_SOURCES} ${LM_EDHOC_SOURCES} ${lm_bench_sources}
    INCLUDE_DIRS "${LM_COMPONENT_REPO}/api" "${CMAKE_CURRENT_LIST_DIR}/include" ${lm_bench_include}
    PRIV_INCLUDE_DIRS "${LM_COMPONENT_REPO}/src" "${lm_gen}" ${LM_EDHOC_PUBLIC_INCLUDE}
                      ${LM_EDHOC_PRIVATE_INCLUDE}
    PRIV_REQUIRES mbedtls esp_timer esp_system nvs_flash nvs_sec_provider esp_partition esp_wifi esp_event
                  esp_netif freertos esp_driver_usb_serial_jtag esp_pm esp_hw_support app_update bootloader_support)

set_source_files_properties(${LM_EDHOC_SOURCES} PROPERTIES COMPILE_OPTIONS "${LM_EDHOC_OPTIONS}")
target_compile_definitions(${COMPONENT_LIB} PRIVATE LM_BUILD_PROFILE_${lm_profile}
                                                    ${LM_EDHOC_DEFINITIONS})
if(CONFIG_LEANMESH_OTA)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE LM_OTA=1)
endif()
if(CONFIG_LEANMESH_OBJECT_TRANSFER)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE LM_OBJECT_TRANSFER=1)
endif()
# First-party code is C++17 without exceptions/RTTI; libedhoc/zcbor are C11 (docs/15 §2).
target_compile_options(${COMPONENT_LIB} PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=gnu++17 -fno-exceptions -fno-rtti -Wshadow>
    $<$<COMPILE_LANGUAGE:C>:-std=gnu11>)
