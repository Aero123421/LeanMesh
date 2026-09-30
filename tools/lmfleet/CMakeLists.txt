# TEST-ONLY. Never referenced by the IDF component or any firmware project.
add_library(lm_fleet STATIC fleet.cpp)
target_include_directories(lm_fleet PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(lm_fleet PRIVATE ${LM_CXX_WARNINGS} -fno-exceptions -fno-rtti)
target_link_libraries(lm_fleet PUBLIC lm_sim)
