set(field_srcs main.c field_app.c field_proto.c field_led.c)
if(CONFIG_FIELD_HUB75)
    if(NOT IDF_TARGET STREQUAL "esp32s3")
        message(FATAL_ERROR "CONFIG_FIELD_HUB75 (the display build) is esp32s3 only")
    endif()
    # The panel library (managed component, main/idf_component.yml, pinned to 3.0.14) does not compile against
    # ESP-IDF v6 (GDMA API): one small local patch, applied here at configure time (after the component manager has
    # fetched the library, before anything is compiled), idempotent. THIRD-PARTY-LICENSES.md section 1b.
    set(hub75_dir "${CMAKE_CURRENT_LIST_DIR}/../managed_components/esp32-hub75-matrixpanel-dma")
    set(hub75_patch "${CMAKE_CURRENT_LIST_DIR}/../../../third_party/patches/esp32-hub75-matrixpanel-dma-3.0.14-idf6-gdma.patch")
    if(EXISTS "${hub75_dir}/src")
        find_program(PATCH_PROGRAM patch)
        if(NOT PATCH_PROGRAM)
            message(FATAL_ERROR "the display build needs the `patch` program (HUB75 library patch)")
        endif()
        file(READ "${hub75_dir}/src/platforms/esp32s3/gdma_lcd_parallel16.cpp" hub75_gdma)
        string(FIND "${hub75_gdma}" "ESP_IDF_VERSION_VAL(6, 0, 0)" hub75_patched) # what the patch adds
        if(hub75_patched EQUAL -1)
            execute_process(COMMAND "${PATCH_PROGRAM}" -p1 -s -i "${hub75_patch}"
                            WORKING_DIRECTORY "${hub75_dir}" RESULT_VARIABLE hub75_rc)
            if(NOT hub75_rc EQUAL 0)
                message(FATAL_ERROR "HUB75 library patch ${hub75_patch} does not apply to ${hub75_dir}")
            endif()
            message(STATUS "HUB75 library: IDF v6 GDMA patch applied")
        endif()
    endif()
    list(APPEND field_srcs field_display_hub75.cpp field_render.c)
else()
    list(APPEND field_srcs field_display_none.c)
endif()

idf_component_register(SRCS ${field_srcs}
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES leanmesh bench_console nvs_flash esp_driver_gpio esp_driver_usb_serial_jtag esp_system esp_timer esp_hw_support)
