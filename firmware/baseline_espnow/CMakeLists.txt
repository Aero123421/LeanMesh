# docs/16 comparison baseline: an empty ESP-IDF app that only brings up ESP-NOW.
# No LeanMesh SDK code is linked here. Build with scripts/build_targets.sh.
cmake_minimum_required(VERSION 3.22)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(leanmesh_baseline_espnow)
