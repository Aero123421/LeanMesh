# Build-only gate (G2): proves that the pinned libedhoc and IDF's PSA (mbedtls component) compile
# and link for the target through the leanmesh component. It is never flashed by any script; if it
# is run it prints known-answer results. Not a product image and not a size reference.
cmake_minimum_required(VERSION 3.22)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(leanmesh_crypto_link_check)
