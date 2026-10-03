# BENCH / HIL ONLY: shared console + provisioning console of firmware/hil_node and firmware/field_node.
idf_component_register(SRCS "bench_console.c"
                       INCLUDE_DIRS "include"
                       REQUIRES leanmesh freertos
                       PRIV_REQUIRES esp_driver_usb_serial_jtag esp_driver_gpio esp_system)
