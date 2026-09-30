# docs/16 comparison sample: same bring-up as firmware/baseline_espnow plus the LeanMesh
# component. Its map/size difference against the baseline is the SDK cost for this target.
# Build with scripts/build_targets.sh --app example_node. Never flashed by any script.
cmake_minimum_required(VERSION 3.22)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(leanmesh_example_node)
