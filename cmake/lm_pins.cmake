# Pin checks shared by the native build and the IDF component.
# config/dependencies.json is the single source of truth for the ESP-IDF commit; the IDF tree also
# provides the mbedTLS/TF-PSA-Crypto sources used by the native build, so a mismatch is fatal.
include_guard(GLOBAL)

set(LM_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." CACHE INTERNAL "")
get_filename_component(LM_REPO_ROOT "${LM_REPO_ROOT}" ABSOLUTE)

function(lm_read_idf_pin out_var)
    file(READ "${LM_REPO_ROOT}/config/dependencies.json" deps)
    string(JSON pin GET "${deps}" esp_idf commit)
    set(${out_var} "${pin}" PARENT_SCOPE)
endfunction()

# Fails configuration when the ESP-IDF checkout is not the pinned, unmodified commit.
function(lm_verify_idf_pin idf_path)
    lm_read_idf_pin(pin)
    find_package(Git REQUIRED)
    execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${idf_path}" rev-parse HEAD
                    OUTPUT_VARIABLE head OUTPUT_STRIP_TRAILING_WHITESPACE
                    RESULT_VARIABLE rc ERROR_QUIET)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "ESP-IDF at '${idf_path}' is not a git checkout; pinned ${pin}")
    endif()
    if(NOT head STREQUAL pin)
        message(FATAL_ERROR "ESP-IDF HEAD ${head} != pinned ${pin} (config/dependencies.json)")
    endif()
    execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${idf_path}" status --porcelain
                            --untracked-files=no --ignore-submodules=none
                            components/mbedtls
                    OUTPUT_VARIABLE dirty OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(dirty)
        message(FATAL_ERROR "ESP-IDF mbedtls component has local modifications:\n${dirty}")
    endif()
endfunction()

# Runs scripts/third_party.sh verify (libedhoc/zcbor pins and the exact-input patch state).
function(lm_verify_third_party)
    execute_process(COMMAND bash "${LM_REPO_ROOT}/scripts/third_party.sh" verify
                    OUTPUT_VARIABLE out ERROR_VARIABLE err RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "third_party verify failed (run scripts/third_party.sh setup):\n${out}${err}")
    endif()
endfunction()
