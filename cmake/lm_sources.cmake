# Source lists shared by the native build and the IDF component. Every module directory owns a
# sources.cmake that appends explicit file names (no globbing) to one of:
#   LM_COMMON_SOURCES     compiled for every role (core, wire, security, store, capi...)
#   LM_ROOT_SOURCES       root-capable builds only (src/root, src/serial)
#   LM_PORT_SIM_SOURCES   simulation ports (native only)
#   LM_PORT_IDF_SOURCES   ESP-IDF ports (firmware only)
# The module list below is the planned layout of docs/IMPLEMENTATION.md §3; a missing directory is
# simply skipped, so slices create their directory and sources.cmake without editing this file.
# No include_guard: the lists are directory-scoped variables and every includer needs them.
include("${CMAKE_CURRENT_LIST_DIR}/lm_pins.cmake")

set(LM_COMMON_SOURCES "")
set(LM_ROOT_SOURCES "")
set(LM_PORT_SIM_SOURCES "")
set(LM_PORT_IDF_SOURCES "")
set(LM_MODULE_DIRS
    core core/wire core/radio core/link core/member core/route core/delivery core/sched
    core/group core/channel core/power core/diag core/ota
    security store capi root serial
    port/sim port/idf)
foreach(dir IN LISTS LM_MODULE_DIRS)
    include("${LM_REPO_ROOT}/src/${dir}/sources.cmake" OPTIONAL)
endforeach()
