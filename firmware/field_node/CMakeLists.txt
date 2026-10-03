# BENCH / FIELD TEST ONLY: the node application of the field test kit (docs/field/protocol.md). Not a product image
# (plaintext NVS, RF approved for a bench, test fleet). One image per role and board:
#   scripts/field.sh build <relay|leaf|display> [target]
# An unprovisioned board answers the same line console as firmware/hil_node (tools/hil/hil.py provision ...); a
# provisioned one joins, sends telemetry and answers pings by itself. `display` = RELAY + CONFIG_FIELD_HUB75 (S3 only).
cmake_minimum_required(VERSION 3.22)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components" "${CMAKE_CURRENT_LIST_DIR}/../common/bench_console")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(leanmesh_field_node)
