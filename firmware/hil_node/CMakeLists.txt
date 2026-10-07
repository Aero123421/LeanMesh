# BENCH / HIL ONLY: firmware for the first hardware runs (Issue #6). One image per role (Kconfig profile):
# an unprovisioned board answers a line console on its USB-Serial/JTAG port (on-board key generation and record
# provisioning, leanmesh_bench.h); a provisioned one starts the mesh. A LEAF/RELAY board keeps the console for
# join/send/status; a ROOT board gives the port to the Host's binary USB session (its console is off).
# Build with scripts/hil.sh build <root|leaf|relay> [target]. Never a product image (plaintext NVS, RF approved
# for a bench, test fleet). The console and provisioning console are the shared firmware/common/bench_console.
cmake_minimum_required(VERSION 3.22)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components" "${CMAKE_CURRENT_LIST_DIR}/../common/bench_console")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(leanmesh_hil_node)
