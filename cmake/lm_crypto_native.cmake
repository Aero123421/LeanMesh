# Native (host/sim) crypto backend: TF-PSA-Crypto from the pinned ESP-IDF tree
# (components/mbedtls/mbedtls/tf-psa-crypto, Mbed TLS 4.1.x fork). This is the same PSA source
# the IDF `mbedtls` component compiles; the native build uses its software (builtin) drivers and the
# default crypto_config.h, while IDF builds add ESP hardware drivers per sdkconfig. There is no
# second crypto library in the tree (docs/06 §2).
include_guard(GLOBAL)
include("${CMAKE_CURRENT_LIST_DIR}/lm_pins.cmake")

function(lm_add_native_crypto idf_path)
    lm_verify_idf_pin("${idf_path}")
    set(src "${idf_path}/components/mbedtls/mbedtls/tf-psa-crypto")
    if(NOT EXISTS "${src}/CMakeLists.txt")
        message(FATAL_ERROR "TF-PSA-Crypto not found at ${src} (ESP-IDF submodules not initialised?)")
    endif()
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(GEN_FILES OFF CACHE BOOL "" FORCE)
    set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF CACHE BOOL "" FORCE)
    set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON CACHE BOOL "" FORCE)
    set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
    # The Espressif fork includes "mbedtls/bignum.h" / "mbedtls/ecp.h" via IDF port wrappers.
    include_directories(BEFORE "${LM_REPO_ROOT}/cmake/native_crypto_compat")
    # Position independent: the same objects are linked into the host's native binding (.so).
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    add_subdirectory("${src}" "${CMAKE_BINARY_DIR}/third_party/tf-psa-crypto" EXCLUDE_FROM_ALL SYSTEM)
    add_library(lm_psa INTERFACE)
    target_link_libraries(lm_psa INTERFACE tfpsacrypto)
endfunction()
