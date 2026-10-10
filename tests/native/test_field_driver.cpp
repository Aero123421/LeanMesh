#include "lmtest.hpp"
#include "VL53L1X.h"
#include "field_acquisition.h"
#include <array>
#include <cstring>

namespace {
std::array<uint8_t, 65536> registers{};
uint16_t fail_read = 0xffff, fail_write = 0xffff;
unsigned transactions;
int64_t fake_us;
int64_t stop_at_us;
struct StopService {};
void (*service_task)(void *);
void *service_arg;
uint32_t key_speed, sensor_speed;
uint8_t key_registers[4] = {0xff, 0, 0xff, 0xa1};
bool exercise_learning, acknowledged_learning, resumed_k3;
field_k3_t competing_k3{};
void put16(uint16_t reg, uint16_t value) {
    registers[reg] = value >> 8;
    registers[reg + 1] = value;
}
void reset_bus() {
    registers.fill(0);
    put16(VL53L1X::IDENTIFICATION__MODEL_ID, 0xeacc);
    put16(VL53L1X::OSC_MEASURED__FAST_OSC__FREQUENCY, 0x1000);
    put16(VL53L1X::RESULT__OSC_CALIBRATE_VAL, 1);
    registers[VL53L1X::FIRMWARE__SYSTEM_STATUS] = 1;
    fail_read = fail_write = 0xffff;
    fake_us = 0;
    transactions = 0;
}
VL53L1X configured() {
    VL53L1X driver;
    driver.setDevice(reinterpret_cast<void *>(1));
    driver.setTimeout(100);
    LM_CHECK(driver.init());
    LM_CHECK(driver.setDistanceMode(VL53L1X::Long));
    LM_CHECK(driver.setMeasurementTimingBudget(33000));
    driver.setROISize(8, 8);
    driver.setROICenter(199);
    driver.startContinuous(40);
    LM_CHECK(driver.last_status == ESP_OK);
    return driver;
}
void measurement(uint8_t status, uint8_t stream) {
    registers[VL53L1X::GPIO__TIO_HV_STATUS] = 0;
    registers[VL53L1X::RESULT__RANGE_STATUS] = status;
    registers[VL53L1X::RESULT__RANGE_STATUS + 2] = stream;
    put16(VL53L1X::RESULT__RANGE_STATUS + 3, 100);
    put16(VL53L1X::RESULT__RANGE_STATUS + 13, 2048);
    put16(VL53L1X::RESULT__RANGE_STATUS + 15, 128);
}
}

esp_err_t i2c_master_transmit(i2c_master_dev_handle_t device, const uint8_t *b, size_t n, int timeout) {
    if (device == reinterpret_cast<void *>(2)) {
        LM_CHECK(timeout == 20 && n == 2 && b[0] < 4);
        key_registers[b[0]] = b[1];
        return ESP_OK;
    }
    LM_CHECK(timeout > 0 && timeout <= 20 && n >= 3 && n <= 6);
    ++transactions;
    const uint16_t reg = static_cast<uint16_t>(b[0]) << 8 | b[1];
    if (reg == fail_write) return ESP_FAIL;
    std::memcpy(registers.data() + reg, b + 2, n - 2);
    return ESP_OK;
}
esp_err_t i2c_master_transmit_receive(i2c_master_dev_handle_t device, const uint8_t *b, size_t n,
                                     uint8_t *out, size_t count, int timeout) {
    if (device == reinterpret_cast<void *>(2)) {
        LM_CHECK(timeout == 20 && n == 1 && count == 1 && b[0] < 4);
        *out = key_registers[b[0]];
        return ESP_OK;
    }
    LM_CHECK(timeout > 0 && timeout <= 20 && n == 2);
    ++transactions;
    const uint16_t reg = static_cast<uint16_t>(b[0]) << 8 | b[1];
    if (reg == fail_read) return ESP_FAIL;
    std::memcpy(out, registers.data() + reg, count);
    return ESP_OK;
}
int64_t esp_timer_get_time() { return fake_us; }
void esp_rom_delay_us(unsigned us) { fake_us += us; }
void vTaskDelay(unsigned ms) {
    fake_us += ms * 1000;
    if (exercise_learning) {
        const uint64_t now = static_cast<uint64_t>(fake_us / 1000);
        const bool pressed = (now >= 1100 && now < 1300) || (now >= 5000 && now < 5200) ||
                             (now >= 9000 && now < 9200) || (now >= 11200 && now < 11400);
        key_registers[0] = pressed ? 0xfd : 0xff;
        if (!acknowledged_learning && now >= 8000) {
            field_presence_snapshot_t snapshot{};
            field_acquisition_stats_t stats{};
            field_acquisition_latest(&snapshot, &stats);
            LM_CHECK(snapshot.learn_request == 1 && stats.learning_busy == 1);
            LM_CHECK(stats.learning_feedback.pending && stats.learning_feedback.result == FIELD_LEARN_DONE);
            LM_CHECK(stats.learning_feedback.visible_until_ms == 0); // not lost after acquisition's former 3s timer
            LM_CHECK(field_feedback_select(&stats.learning_feedback, &competing_k3, snapshot.learning, now) == FIELD_FEEDBACK_LEARN_DONE);
            field_acquisition_feedback_shown(stats.learning_feedback.token, now); // simulated successful main frame
            acknowledged_learning = true;
        }
        if (acknowledged_learning && !resumed_k3 && now >= 11000) {
            field_presence_snapshot_t snapshot{};
            field_acquisition_stats_t stats{};
            field_acquisition_latest(&snapshot, &stats);
            LM_CHECK(field_feedback_select(&stats.learning_feedback, &competing_k3, snapshot.learning, now) == FIELD_FEEDBACK_SENDING);
            resumed_k3 = true;
        }
    }
    if (stop_at_us != 0 && fake_us >= stop_at_us) throw StopService{};
}
int xTaskCreate(void (*task)(void *), const char *, uint32_t stack, void *arg, unsigned priority, void **handle) {
    LM_CHECK(stack == 6144 && priority == 4);
    service_task = task;
    service_arg = arg;
    *handle = reinterpret_cast<void *>(3);
    return 1;
}
esp_err_t i2c_new_master_bus(const i2c_master_bus_config_t *cfg, void **bus) {
    LM_CHECK((cfg->i2c_port == 0 && cfg->sda_io_num == 1 && cfg->scl_io_num == 2) ||
             (cfg->i2c_port == 1 && cfg->sda_io_num == 43 && cfg->scl_io_num == 44));
    *bus = reinterpret_cast<void *>(cfg->i2c_port == 0 ? 2 : 1);
    return ESP_OK;
}
esp_err_t i2c_master_bus_add_device(void *bus, const i2c_device_config_t *cfg, void **device) {
    if (bus == reinterpret_cast<void *>(2)) {
        LM_CHECK(cfg->device_address == 0x19);
        key_speed = cfg->scl_speed_hz;
    } else {
        LM_CHECK(cfg->device_address == 0x29);
        sensor_speed = cfg->scl_speed_hz;
    }
    *device = bus;
    return ESP_OK;
}

LM_TEST("FIELD actual VL53L1X KG settings retain ST calibration gain and mapped status") {
    reset_bus();
    auto driver = configured();
    LM_CHECK(driver.getDistanceMode() == VL53L1X::Long);
    LM_CHECK(driver.getMeasurementTimingBudget() >= 32000 && driver.getMeasurementTimingBudget() <= 34000);
    uint8_t w, h;
    driver.getROISize(&w, &h);
    LM_CHECK(w == 8 && h == 8 && driver.getROICenter() == 199);
    LM_CHECK(driver.readReg32Bit(VL53L1X::SYSTEM__INTERMEASUREMENT_PERIOD) == 40);
    measurement(9, 1);
    driver.clearError();
    LM_CHECK(driver.dataReady());
    LM_CHECK(driver.read(false) == 2011); // actual ST gain conversion, not raw register mm
    LM_CHECK(driver.ranging_data.range_status == VL53L1X::RangeValid);
    measurement(9, 0);
    LM_CHECK(driver.read(false) == 2011);
    LM_CHECK(driver.ranging_data.range_status == VL53L1X::RangeValidNoWrapCheckFail);
    measurement(6, 1);
    (void)driver.read(false);
    LM_CHECK(driver.ranging_data.range_status == VL53L1X::SigmaFail);
}

LM_TEST("FIELD actual VL53L1X NACK or failed interrupt clear never becomes valid stale data") {
    reset_bus();
    auto driver = configured();
    measurement(9, 1);
    fail_read = VL53L1X::GPIO__TIO_HV_STATUS;
    driver.clearError();
    LM_CHECK(!driver.dataReady() && driver.last_status != ESP_OK);
    fail_read = 0xffff;
    LM_CHECK(!driver.dataReady()); // sticky until the next cycle, not a false ready
    driver.clearError();
    fail_read = VL53L1X::RESULT__RANGE_STATUS;
    LM_CHECK(driver.read(false) == 0 && driver.ranging_data.range_status == VL53L1X::None);
    fail_read = 0xffff;
    fail_write = VL53L1X::SYSTEM__INTERRUPT_CLEAR;
    driver.clearError();
    LM_CHECK(driver.read(false) == 0 && driver.ranging_data.range_status == VL53L1X::None);
    fail_write = 0xffff;
    driver.clearError();
    LM_CHECK(driver.dataReady() && driver.read(false) == 2011);
}

LM_TEST("FIELD actual VL53L1X missing boot completion has a finite initialization budget") {
    reset_bus();
    registers[VL53L1X::FIRMWARE__SYSTEM_STATUS] = 0;
    VL53L1X driver;
    driver.setDevice(reinterpret_cast<void *>(1));
    driver.setTimeout(100);
    LM_CHECK(!driver.init() && driver.timeoutOccurred());
    LM_CHECK(fake_us < 130000 && transactions < 130);
}

LM_TEST("FIELD real acquisition service configures keys 100k and sensor 400k independently") {
    reset_bus();
    measurement(9, 1);
    exercise_learning = true;
    LM_CHECK(field_k3_press(&competing_k3, 1, 100, 100));
    field_k3_accepted(&competing_k3, 42);
    LM_CHECK(field_acquisition_start());
    stop_at_us = 11400000;
    try { service_task(service_arg); } catch (const StopService &) {}
    stop_at_us = 0;
    exercise_learning = false;
    LM_CHECK(key_speed == 100000 && sensor_speed == 400000);
    LM_CHECK(key_registers[2] == 0xf9 && key_registers[3] == 0xa7);
    field_presence_snapshot_t latest{};
    field_acquisition_stats_t stats{};
    field_acquisition_latest(&latest, &stats);
    LM_CHECK((latest.flags & FIELD_KEYS_READY) != 0);
    LM_CHECK(acknowledged_learning && resumed_k3);
    LM_CHECK(stats.learning_busy == 2 && latest.learn_request == 2 && latest.learning == FIELD_LEARN_RUNNING);
    LM_CHECK(!stats.learning_feedback.pending); // next learning allowed only after visible completion retired
}

LM_TEST_MAIN()
