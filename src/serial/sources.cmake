# USB serial (S10): framing, session state machine shared with the Host's native helper, root
# adapter and pairing record. Root builds only (LM_ROOT_SOURCES); the bridge (S13, bridge*.cpp) is the sink of the ACTIVE session.
list(APPEND LM_ROOT_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/cobs.cpp
    ${CMAKE_CURRENT_LIST_DIR}/usb_link.cpp
    ${CMAKE_CURRENT_LIST_DIR}/usb_handshake.cpp
    ${CMAKE_CURRENT_LIST_DIR}/pairing.cpp
    ${CMAKE_CURRENT_LIST_DIR}/root_usb.cpp
    ${CMAKE_CURRENT_LIST_DIR}/bridge.cpp
    ${CMAKE_CURRENT_LIST_DIR}/bridge_methods.cpp)

# ESP-IDF USB-Serial/JTAG transport of the root: compiled only in the ROOT profile of the component.
set(LM_ROOT_IDF_SOURCES ${CMAKE_CURRENT_LIST_DIR}/idf_serial.cpp)
