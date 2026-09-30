# libedhoc (pinned submodule third_party/libedhoc, exact-input patch applied) + its zcbor.
# Only the protocol core and the CBOR backend are compiled. libedhoc's reference cipher suites are
# NOT compiled: LeanMesh provides the single suite-3 (P-256/ES256/AES-CCM-16-128-128/SHA-256)
# crypto glue over PSA in src/security (docs/06 §2, docs/IMPLEMENTATION.md §5).
# Shared by the native build and the IDF component; the upstream source list is reused verbatim.
include_guard(GLOBAL)
include("${CMAKE_CURRENT_LIST_DIR}/lm_pins.cmake")

# Sets in the caller's scope:
#   LM_EDHOC_SOURCES        C sources (libedhoc core + CBOR backend + zcbor)
#   LM_EDHOC_PUBLIC_INCLUDE include dirs needed by users of <edhoc/edhoc.h>
#   LM_EDHOC_PRIVATE_INCLUDE include dirs needed only to compile the sources
#   LM_EDHOC_DEFINITIONS    compile definitions for the sources
#   LM_EDHOC_OPTIONS        compile options for the vendor sources: zcbor's float16 helpers use
#                           type punning (-fno-strict-aliasing makes that defined behaviour);
#                           vendor warnings stay visible in the log but do not fail the build
# and generates <config_dir>/edhoc_config.h.
function(lm_edhoc_collect config_dir)
    # Function-relative path: include_guard(GLOBAL) means directory-scoped variables set at include
    # time are not visible in other directories (e.g. a second IDF component).
    set(LM_EDHOC_ROOT "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../third_party/libedhoc")
    if(NOT EXISTS "${LM_EDHOC_ROOT}/cmake/sources.cmake")
        message(FATAL_ERROR "libedhoc checkout incomplete; run scripts/third_party.sh setup")
    endif()
    # LeanMesh configuration, sized for suite 3 (T03): P-256 x-only G_X/G_Y are 32 B and the only
    # MAC-sized buffer is the SHA-256 transcript hash. Two suite slots exist only so the RFC 9529
    # trace (SUITES_I = [6, 2]) can be replayed in tests; the product offers suite 3 alone.
    set(CONFIG_LIBEDHOC_ENABLE 1)
    set(CONFIG_LIBEDHOC_KEY_ID_LEN 4)                 # psa_key_id_t handle
    set(CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES 2)    # product: suite 3 only (see above)
    set(CONFIG_LIBEDHOC_MAX_NR_OF_METHODS 1)          # method 0 only
    set(CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID 7)
    set(CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_ENCAPSULATION_KEY 32)
    set(CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT 32)
    set(CONFIG_LIBEDHOC_MAX_LEN_OF_MAC 32)
    set(CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS 3)
    set(CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID 32)    # kid = full DeviceId (docs/06 §4)
    set(CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN 1)
    set(CONFIG_LIBEDHOC_LOG_LEVEL 0)                  # never log handshake material
    set(CONFIG_LIBEDHOC_MEM_BACKEND 0)                # stack; runs on the slow-job worker
    foreach(suite 0 2 4 24 PQC_1)
        set(CONFIG_LIBEDHOC_CIPHER_SUITE_${suite}_ENABLE 0)
    endforeach()
    configure_file("${LM_EDHOC_ROOT}/cmake/edhoc_config.h.in" "${config_dir}/edhoc_config.h" @ONLY)

    include("${LM_EDHOC_ROOT}/cmake/sources.cmake")
    include("${LM_EDHOC_ROOT}/cmake/externals_sources.cmake")
    set(LM_EDHOC_SOURCES ${LIBEDHOC_CORE_SOURCES} ${LIBEDHOC_BACKEND_CBOR_SOURCES}
                         ${LIBEDHOC_ZCBOR_SOURCES} PARENT_SCOPE)
    set(LM_EDHOC_PUBLIC_INCLUDE "${LIBEDHOC_PUBLIC_INCLUDE_DIR}" "${config_dir}" PARENT_SCOPE)
    set(LM_EDHOC_PRIVATE_INCLUDE "${LIBEDHOC_INTERNAL_INCLUDE_DIR}" "${LIBEDHOC_BACKEND_CBOR_INCLUDE_DIR}"
                                 "${LIBEDHOC_BACKEND_MEM_INCLUDE_DIR}" "${LIBEDHOC_BACKEND_LOG_INCLUDE_DIR}"
                                 "${LIBEDHOC_ZCBOR_INCLUDE_DIR}" PARENT_SCOPE)
    set(LM_EDHOC_DEFINITIONS ${LIBEDHOC_ZCBOR_COMPILE_DEFINITIONS} PARENT_SCOPE)
    set(_lm_edhoc_options -fno-strict-aliasing -Wno-error)
    if(LM_SANITIZE)
        # zcbor's str_encode() calls memmove(dst, NULL, 0) for an empty external_aad. Benign on the
        # supported libcs and left unpatched (THIRD-PARTY-LICENSES.md, T03 decision); silenced for
        # vendor code only so that sanitizer output of first-party code stays meaningful.
        list(APPEND _lm_edhoc_options -fno-sanitize=nonnull-attribute)
    endif()
    set(LM_EDHOC_OPTIONS ${_lm_edhoc_options} PARENT_SCOPE)
endfunction()
