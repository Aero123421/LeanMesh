# Wire codecs (WIRE slice): deterministic CBOR, link/route/end/fragment/HOP_ACK/serial/power layouts,
# control-body envelope and COSE_Sign1 structure. Pure functions, no I/O.
list(APPEND LM_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/cbor_reader.cpp
    ${CMAKE_CURRENT_LIST_DIR}/control.cpp
    ${CMAKE_CURRENT_LIST_DIR}/frame.cpp
    ${CMAKE_CURRENT_LIST_DIR}/transfer.cpp
    ${CMAKE_CURRENT_LIST_DIR}/serial_header.cpp
    ${CMAKE_CURRENT_LIST_DIR}/power_frame.cpp)
