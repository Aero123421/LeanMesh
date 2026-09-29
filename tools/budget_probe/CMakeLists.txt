# Budget probe (scripts/budget_report.py): sizeof of the owner objects for each compile-time profile.
# Static libraries of one object file each, never linked into a program; the report reads the symbol
# sizes with nm. Built in every native build so a renamed or removed type fails the build, not the
# report.
foreach(profile LEAF RELAY ROOT)
    string(TOLOWER "${profile}" p)
    add_library(lm_budget_probe_${p} STATIC probe.cpp)
    target_include_directories(lm_budget_probe_${p} PRIVATE "${LM_REPO_ROOT}/api" "${LM_REPO_ROOT}/src"
                               "${LM_GEN_DIR}" ${LM_EDHOC_PUBLIC_INCLUDE})
    target_compile_definitions(lm_budget_probe_${p} PRIVATE LM_BUILD_PROFILE_${profile})
    target_compile_options(lm_budget_probe_${p} PRIVATE ${LM_CXX_WARNINGS} -fno-exceptions -fno-rtti)
endforeach()
