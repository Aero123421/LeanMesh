#pragma once
// Native fake transport for testing the actual vendored driver. No hardware claims.
#include <stddef.h>
#include <stdint.h>
typedef int esp_err_t;
enum { ESP_OK = 0, ESP_ERR_INVALID_STATE = 1, ESP_ERR_INVALID_SIZE = 2, ESP_FAIL = 3 };
typedef void *i2c_master_dev_handle_t;
typedef void *i2c_master_bus_handle_t;
typedef int i2c_port_num_t;
typedef int gpio_num_t;
enum { I2C_NUM_0 = 0, I2C_NUM_1 = 1, I2C_CLK_SRC_DEFAULT = 0, I2C_ADDR_BIT_LEN_7 = 0 };
typedef struct {
    i2c_port_num_t i2c_port;
    gpio_num_t sda_io_num, scl_io_num;
    int clk_source;
    uint8_t glitch_ignore_cnt;
} i2c_master_bus_config_t;
typedef struct {
    int dev_addr_length;
    uint16_t device_address;
    uint32_t scl_speed_hz;
} i2c_device_config_t;
esp_err_t i2c_new_master_bus(const i2c_master_bus_config_t *, i2c_master_bus_handle_t *);
esp_err_t i2c_master_bus_add_device(i2c_master_bus_handle_t, const i2c_device_config_t *, i2c_master_dev_handle_t *);
esp_err_t i2c_master_transmit(i2c_master_dev_handle_t, const uint8_t *, size_t, int);
esp_err_t i2c_master_transmit_receive(i2c_master_dev_handle_t, const uint8_t *, size_t, uint8_t *, size_t, int);
