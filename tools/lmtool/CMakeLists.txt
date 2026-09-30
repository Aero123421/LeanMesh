# lmtool: codec CLI for the differential wire tests (test tool, never part of a firmware image).
add_executable(lmtool main.cpp)
target_compile_options(lmtool PRIVATE ${LM_CXX_WARNINGS})
target_link_libraries(lmtool PRIVATE lm_sdk)
