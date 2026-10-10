// Display application I/O owner. No SDK, logging, Flash or rendering here.
#include "field_acquisition.h"
#include "field_presence.h"
#include "sdkconfig.h"
#include <driver/i2c_master.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <algorithm>
#ifndef CONFIG_FIELD_TOF
#define CONFIG_FIELD_TOF 0
#endif
#if CONFIG_FIELD_TOF
#include "VL53L1X.h"
#endif

namespace {
constexpr int kTimeoutMs = 20;
constexpr uint64_t kKeyPeriodMs = 25;
constexpr uint64_t kSamplePeriodMs = 40;
constexpr uint64_t kInitRetryMs = 3000;
constexpr uint32_t kStackBytes = 6144;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
field_keys_t keys{};
field_presence_snapshot_t latest{};
field_acquisition_stats_t stats{};
field_learning_feedback_t learning_feedback{};
TaskHandle_t task_handle;
i2c_master_bus_handle_t key_bus;
i2c_master_dev_handle_t key_device;
bool key_configured;
#if CONFIG_FIELD_TOF
i2c_master_bus_handle_t sensor_bus;
i2c_master_dev_handle_t sensor_device;
VL53L1X sensor;
bool sensor_ready;
uint64_t last_sensor_answer_ms;
#endif
uint64_t clock_ms() { return static_cast<uint64_t>(esp_timer_get_time() / 1000); }
void count(uint32_t &n) { if (n != UINT32_MAX) ++n; }
// Caller holds mux. Observe both before K1 admission and when publishing: a
// completion between snapshot ticks must be retained before another request.
void observe_learning(uint8_t state, uint8_t &previous) {
    if (state != previous && (state == FIELD_LEARN_DONE || state == FIELD_LEARN_FAILED))
        (void)field_learning_feedback_offer(&learning_feedback, state);
    previous = state;
}

bool make_bus(i2c_port_num_t port, int sda, int scl, uint8_t address, uint32_t clock_hz,
              i2c_master_bus_handle_t &bus, i2c_master_dev_handle_t &device) {
    if (bus == nullptr) {
        i2c_master_bus_config_t cfg{};
        cfg.i2c_port = port;
        cfg.sda_io_num = static_cast<gpio_num_t>(sda);
        cfg.scl_io_num = static_cast<gpio_num_t>(scl);
        cfg.clk_source = I2C_CLK_SRC_DEFAULT;
        cfg.glitch_ignore_cnt = 7;
        // Real external pull-ups required; weak internal pull-ups are not evidence.
        if (i2c_new_master_bus(&cfg, &bus) != ESP_OK) return false;
    }
    if (device == nullptr) {
        i2c_device_config_t cfg{};
        cfg.dev_addr_length = I2C_ADDR_BIT_LEN_7;
        cfg.device_address = address;
        cfg.scl_speed_hz = clock_hz;
        if (i2c_master_bus_add_device(bus, &cfg, &device) != ESP_OK) return false;
    }
    return true;
}
bool key_read(uint8_t reg, uint8_t &value) {
    return i2c_master_transmit_receive(key_device, &reg, 1, &value, 1, kTimeoutMs) == ESP_OK;
}
bool key_write(uint8_t reg, uint8_t value) {
    const uint8_t b[] = {reg, value};
    return i2c_master_transmit(key_device, b, sizeof b, kTimeoutMs) == ESP_OK;
}
bool key_init() {
    if (!make_bus(I2C_NUM_0, 1, 2, 0x19, 100000, key_bus, key_device)) return false;
    uint8_t polarity, config;
    // Read-modify-write ONLY the two keys. Other expander outputs are preserved.
    return key_read(2, polarity) && key_read(3, config) &&
        key_write(2, field_keys_polarity(polarity)) && key_write(3, field_keys_config(config));
}
#if CONFIG_FIELD_TOF
bool sensor_init() {
    if (!make_bus(I2C_NUM_1, 43, 44, 0x29, 400000, sensor_bus, sensor_device)) return false;
    sensor.setDevice(sensor_device);
    sensor.setTimeout(100);
    if (!sensor.init() || !sensor.setDistanceMode(VL53L1X::Long) ||
        !sensor.setMeasurementTimingBudget(33000)) return false;
    sensor.setROISize(8, 8);
    sensor.setROICenter(199);
    sensor.startContinuous(40);
    return sensor.last_status == ESP_OK;
}
#endif

void service(void *) {
    field_acquisition_stats_t io_stats{};
    const uint64_t boot = clock_ms();
    field_presence_begin(CONFIG_FIELD_TOF, boot);
    uint64_t key_at = boot, key_init_at = boot, sample_at = boot;
    uint64_t sensor_init_at = boot, tick_at = boot;
    uint8_t previous_learning = FIELD_LEARN_IDLE;
    for (;;) {
        uint64_t now = clock_ms();
        if (!key_configured && now >= key_init_at) {
            key_configured = key_init();
            key_init_at = clock_ms() + kInitRetryMs;
        }
        if (now >= key_at) {
            uint8_t input = 0;
            const bool ok = key_configured && key_read(0, input);
            now = clock_ms();
            bool learn = false;
            portENTER_CRITICAL(&mux);
            const uint8_t before = keys.count;
            field_keys_read(&keys, now, ok, input);
            for (unsigned i = before; i < keys.count; ++i)
                learn |= keys.events[(keys.head + i) % FIELD_KEY_QUEUE_CAPACITY].button == 1;
            portEXIT_CRITICAL(&mux);
            if (!ok) {
                count(io_stats.key_errors);
                key_configured = false;
            }
            if (learn) {
                field_presence_snapshot_t state{};
                field_presence_capture(now, &state);
                portENTER_CRITICAL(&mux);
                field_learning_feedback_tick(&learning_feedback, now);
                observe_learning(state.learning, previous_learning);
                const bool blocked = learning_feedback.pending || learning_feedback.token == UINT32_MAX;
                portEXIT_CRITICAL(&mux);
                if (blocked) count(io_stats.learning_busy);
                else if (!field_presence_learn(now)) {
                    field_presence_capture(now, &state);
                    if (state.learning == FIELD_LEARN_NO_SENSOR) {
                        portENTER_CRITICAL(&mux);
                        (void)field_learning_feedback_offer(&learning_feedback, FIELD_LEARN_NO_SENSOR);
                        portEXIT_CRITICAL(&mux);
                    } else count(io_stats.learning_busy);
                }
            }
            do { key_at += kKeyPeriodMs; } while (key_at <= now);
        }
#if CONFIG_FIELD_TOF
        now = clock_ms();
        if (!sensor_ready && now >= sensor_init_at) {
            sensor_ready = sensor_init();
            now = clock_ms();
            field_presence_ready(sensor_ready);
            if (!sensor_ready) count(io_stats.sensor_errors);
            last_sensor_answer_ms = now;
            sensor_init_at = now + kInitRetryMs;
            sample_at = now + kSamplePeriodMs;
        }
        if (sensor_ready && now >= sample_at) {
            sensor.clearError();
            if (sensor.dataReady()) {
                const uint16_t mm = sensor.read(false);
                now = clock_ms();
                if (sensor.last_status == ESP_OK && !sensor.timeoutOccurred()) {
                    field_presence_sample(now, mm, sensor.ranging_data.range_status);
                    last_sensor_answer_ms = now;
                }
            }
            now = clock_ms();
            if (sensor.last_status != ESP_OK || now - last_sensor_answer_ms >= 10000) {
                count(io_stats.sensor_errors);
                sensor_ready = false;
                field_presence_ready(false);
                sensor_init_at = now + kInitRetryMs;
            }
            do { sample_at += kSamplePeriodMs; } while (sample_at <= now);
        }
#else
        (void)sample_at;
        (void)sensor_init_at;
#endif
        now = clock_ms();
        if (now >= tick_at) {
            field_presence_tick(now);
            field_presence_snapshot_t capture{};
            field_presence_capture(now, &capture);
            portENTER_CRITICAL(&mux);
            field_learning_feedback_tick(&learning_feedback, now);
            observe_learning(capture.learning, previous_learning);
            if (keys.ready) capture.flags |= FIELD_KEYS_READY;
            latest = capture; // one latest snapshot, coalescing, no offline history
            io_stats.key_dropped = keys.dropped;
            io_stats.k3_presses = keys.press_seq; // raw count is diagnostic only
            stats = io_stats;
            portEXIT_CRITICAL(&mux);
            tick_at = now + 40;
        }
        uint64_t due = std::min(key_at, tick_at);
        if (!key_configured) due = std::min(due, key_init_at);
#if CONFIG_FIELD_TOF
        due = std::min(due, sensor_ready ? sample_at : sensor_init_at);
#endif
        now = clock_ms();
        const uint64_t delay = due > now ? due - now : 1;
        vTaskDelay(std::max<TickType_t>(1, pdMS_TO_TICKS(delay)));
    }
}
}

bool field_acquisition_start() {
    latest.presence = CONFIG_FIELD_TOF ? FIELD_PRESENCE_UNKNOWN : FIELD_PRESENCE_DISABLED;
    latest.sample_age_ms = latest.distance_mm = latest.background_mm = UINT16_MAX;
    return xTaskCreate(service, "field_io", kStackBytes, nullptr, 4, &task_handle) == pdPASS;
}
void field_acquisition_latest(field_presence_snapshot_t *out, field_acquisition_stats_t *result) {
    portENTER_CRITICAL(&mux);
    *out = latest;
    *result = stats;
    result->learning_feedback = learning_feedback;
    portEXIT_CRITICAL(&mux);
}
bool field_acquisition_key(field_key_event_t *out) {
    portENTER_CRITICAL(&mux);
    const bool found = field_keys_pop(&keys, out);
    portEXIT_CRITICAL(&mux);
    return found;
}
void field_acquisition_feedback_shown(uint32_t token, uint64_t now) {
    portENTER_CRITICAL(&mux);
    field_learning_feedback_shown(&learning_feedback, token, now);
    portEXIT_CRITICAL(&mux);
}
