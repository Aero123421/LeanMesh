# Crypto glue over PSA and libedhoc (CRYPTO slice). edhoc/lm_edhoc.c is C11 (libedhoc headers).
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/crypto.cpp
    ${CMAKE_CURRENT_LIST_DIR}/identity.cpp
    ${CMAKE_CURRENT_LIST_DIR}/record.cpp
    ${CMAKE_CURRENT_LIST_DIR}/cose_sign1.cpp
    ${CMAKE_CURRENT_LIST_DIR}/handshake.cpp
    ${CMAKE_CURRENT_LIST_DIR}/link_check.cpp
    ${CMAKE_CURRENT_LIST_DIR}/edhoc/lm_edhoc.c)
