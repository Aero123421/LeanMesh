// Pololu/ST VL53L1X driver with KG native IDF transport. BSD-3-Clause,
// Copyright (c) 2017 STMicroelectronics; (c) 2018-2022 Pololu Corporation.
// See LICENSE.txt and PROVENANCE.md. Functionality is based on STSW-IMG007;
// comments quote/paraphrase that API, UM2356 and the VL53L1X datasheet.
#include "VL53L1X.h"
#include <cstring>
#include <esp_rom_sys.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

VL53L1X::VL53L1X()
    : device(nullptr), io_timeout(0), did_timeout(false), calibrated(false),
      saved_vhv_init(0), saved_vhv_timeout(0), distance_mode(Unknown) {}

// VL53L1_DataInit + StaticInit, LOWPOWER_AUTONOMOUS preset.
bool VL53L1X::init(bool io_2v8) {
    clearError();
    calibrated = false;
    if (readReg16Bit(IDENTIFICATION__MODEL_ID) != 0xEACC) return false;
    writeReg(SOFT_RESET, 0x00);
    esp_rom_delay_us(100);
    writeReg(SOFT_RESET, 0x01);
    vTaskDelay(pdMS_TO_TICKS(1));
    if (last_status != ESP_OK) return false;
    startTimeout();
    // Reset can temporarily NACK; only this boot-status read clears errors.
    for (;;) {
        clearError();
        if ((readReg(FIRMWARE__SYSTEM_STATUS) & 1) != 0 && last_status == ESP_OK) break;
        if (checkTimeoutExpired()) {
            did_timeout = true;
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    if (io_2v8) writeReg(PAD_I2C_HV__EXTSUP_CONFIG, readReg(PAD_I2C_HV__EXTSUP_CONFIG) | 1);
    fast_osc_frequency = readReg16Bit(OSC_MEASURED__FAST_OSC__FREQUENCY);
    osc_calibrate_val = readReg16Bit(RESULT__OSC_CALIBRATE_VAL);
    if (last_status != ESP_OK || fast_osc_frequency == 0) return false;

    // ST standard-ranging tuning defaults, written once rather than mirrored in RAM.
    writeReg16Bit(DSS_CONFIG__TARGET_TOTAL_RATE_MCPS, TargetRate);
    writeReg(GPIO__TIO_HV_STATUS, 0x02);
    writeReg(SIGMA_ESTIMATOR__EFFECTIVE_PULSE_WIDTH_NS, 8);
    writeReg(SIGMA_ESTIMATOR__EFFECTIVE_AMBIENT_WIDTH_NS, 16);
    writeReg(ALGO__CROSSTALK_COMPENSATION_VALID_HEIGHT_MM, 0x01);
    writeReg(ALGO__RANGE_IGNORE_VALID_HEIGHT_MM, 0xFF);
    writeReg(ALGO__RANGE_MIN_CLIP, 0);
    writeReg(ALGO__CONSISTENCY_CHECK__TOLERANCE, 2);
    writeReg16Bit(SYSTEM__THRESH_RATE_HIGH, 0);
    writeReg16Bit(SYSTEM__THRESH_RATE_LOW, 0);
    writeReg(DSS_CONFIG__APERTURE_ATTENUATION, 0x38);
    writeReg16Bit(RANGE_CONFIG__SIGMA_THRESH, 360);
    writeReg16Bit(RANGE_CONFIG__MIN_COUNT_RATE_RTN_LIMIT_MCPS, 192);
    writeReg(SYSTEM__GROUPED_PARAMETER_HOLD_0, 1);
    writeReg(SYSTEM__GROUPED_PARAMETER_HOLD_1, 1);
    writeReg(SD_CONFIG__QUANTIFIER, 2);
    writeReg(SYSTEM__GROUPED_PARAMETER_HOLD, 0);
    writeReg(SYSTEM__SEED_CONFIG, 1);
    writeReg(SYSTEM__SEQUENCE_CONFIG, 0x8B); // VHV, PHASECAL, DSS1, RANGE
    writeReg16Bit(DSS_CONFIG__MANUAL_EFFECTIVE_SPADS_SELECT, 200 << 8);
    writeReg(DSS_CONFIG__ROI_MODE_CONTROL, 2); // REQUESTED_EFFECTIVE_SPADS
    setDistanceMode(Long);
    setMeasurementTimingBudget(50000);
    writeReg16Bit(ALGO__PART_TO_PART_RANGE_OFFSET_MM, readReg16Bit(MM_CONFIG__OUTER_OFFSET_MM) * 4);
    return last_status == ESP_OK;
}

// Native IDF, big endian addresses, finite timeout and sticky cycle errors.
void VL53L1X::writeBytes(uint16_t reg, const uint8_t *bytes, size_t size) {
    if (last_status != ESP_OK) return;
    if (device == nullptr) { last_status = ESP_ERR_INVALID_STATE; return; }
    uint8_t buffer[6] = {static_cast<uint8_t>(reg >> 8), static_cast<uint8_t>(reg)};
    if (size > sizeof(buffer) - 2) { last_status = ESP_ERR_INVALID_SIZE; return; }
    std::memcpy(buffer + 2, bytes, size);
    last_status = i2c_master_transmit(device, buffer, size + 2, 20);
}
bool VL53L1X::readBytes(uint16_t reg, uint8_t *bytes, size_t size) {
    if (last_status != ESP_OK) return false;
    if (device == nullptr) { last_status = ESP_ERR_INVALID_STATE; return false; }
    const uint8_t address[] = {static_cast<uint8_t>(reg >> 8), static_cast<uint8_t>(reg)};
    last_status = i2c_master_transmit_receive(device, address, 2, bytes, size, 20);
    return last_status == ESP_OK;
}
void VL53L1X::writeReg(uint16_t reg, uint8_t value) { writeBytes(reg, &value, 1); }
void VL53L1X::writeReg16Bit(uint16_t reg, uint16_t value) {
    const uint8_t b[] = {static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
    writeBytes(reg, b, sizeof b);
}
void VL53L1X::writeReg32Bit(uint16_t reg, uint32_t value) {
    const uint8_t b[] = {static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
                         static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
    writeBytes(reg, b, sizeof b);
}
uint8_t VL53L1X::readReg(regAddr reg) {
    uint8_t v = 0;
    readBytes(reg, &v, 1);
    return v;
}
uint16_t VL53L1X::readReg16Bit(uint16_t reg) {
    uint8_t b[2] = {};
    if (!readBytes(reg, b, sizeof b)) return 0;
    return static_cast<uint16_t>(b[0]) << 8 | b[1];
}
uint32_t VL53L1X::readReg32Bit(uint16_t reg) {
    uint8_t b[4] = {};
    if (!readBytes(reg, b, sizeof b)) return 0;
    return static_cast<uint32_t>(b[0]) << 24 | static_cast<uint32_t>(b[1]) << 16 |
           static_cast<uint32_t>(b[2]) << 8 | b[3];
}

// VL53L1_SetDistanceMode, reapplying the existing timing budget.
bool VL53L1X::setDistanceMode(DistanceMode mode) {
    uint32_t budget = getMeasurementTimingBudget();
    switch (mode) {
    case Short:
        writeReg(RANGE_CONFIG__VCSEL_PERIOD_A, 0x07);
        writeReg(RANGE_CONFIG__VCSEL_PERIOD_B, 0x05);
        writeReg(RANGE_CONFIG__VALID_PHASE_HIGH, 0x38);
        writeReg(SD_CONFIG__WOI_SD0, 0x07);
        writeReg(SD_CONFIG__WOI_SD1, 0x05);
        writeReg(SD_CONFIG__INITIAL_PHASE_SD0, 6);
        writeReg(SD_CONFIG__INITIAL_PHASE_SD1, 6);
        break;
    case Medium:
        writeReg(RANGE_CONFIG__VCSEL_PERIOD_A, 0x0B);
        writeReg(RANGE_CONFIG__VCSEL_PERIOD_B, 0x09);
        writeReg(RANGE_CONFIG__VALID_PHASE_HIGH, 0x78);
        writeReg(SD_CONFIG__WOI_SD0, 0x0B);
        writeReg(SD_CONFIG__WOI_SD1, 0x09);
        writeReg(SD_CONFIG__INITIAL_PHASE_SD0, 10);
        writeReg(SD_CONFIG__INITIAL_PHASE_SD1, 10);
        break;
    case Long:
        writeReg(RANGE_CONFIG__VCSEL_PERIOD_A, 0x0F);
        writeReg(RANGE_CONFIG__VCSEL_PERIOD_B, 0x0D);
        writeReg(RANGE_CONFIG__VALID_PHASE_HIGH, 0xB8);
        writeReg(SD_CONFIG__WOI_SD0, 0x0F);
        writeReg(SD_CONFIG__WOI_SD1, 0x0D);
        writeReg(SD_CONFIG__INITIAL_PHASE_SD0, 14);
        writeReg(SD_CONFIG__INITIAL_PHASE_SD1, 14);
        break;
    default:
        return false;
    }
    setMeasurementTimingBudget(budget);
    distance_mode = mode;
    return true;
}

// VL53L1_SetMeasurementTimingBudgetMicroSeconds, LOWPOWER_AUTONOMOUS.
bool VL53L1X::setMeasurementTimingBudget(uint32_t budget) {
    if (budget <= TimingGuard) return false;
    uint32_t range_us = budget - TimingGuard;
    if (range_us > 1100000) return false;
    range_us /= 2;
    uint32_t macro = calcMacroPeriod(readReg(RANGE_CONFIG__VCSEL_PERIOD_A));
    uint32_t phase = timeoutMicrosecondsToMclks(1000, macro);
    if (phase > 0xFF) phase = 0xFF;
    writeReg(PHASECAL_CONFIG__TIMEOUT_MACROP, phase);
    writeReg16Bit(MM_CONFIG__TIMEOUT_MACROP_A, encodeTimeout(timeoutMicrosecondsToMclks(1, macro)));
    writeReg16Bit(RANGE_CONFIG__TIMEOUT_MACROP_A, encodeTimeout(timeoutMicrosecondsToMclks(range_us, macro)));
    macro = calcMacroPeriod(readReg(RANGE_CONFIG__VCSEL_PERIOD_B));
    writeReg16Bit(MM_CONFIG__TIMEOUT_MACROP_B, encodeTimeout(timeoutMicrosecondsToMclks(1, macro)));
    writeReg16Bit(RANGE_CONFIG__TIMEOUT_MACROP_B, encodeTimeout(timeoutMicrosecondsToMclks(range_us, macro)));
    return true;
}
uint32_t VL53L1X::getMeasurementTimingBudget() {
    uint32_t macro = calcMacroPeriod(readReg(RANGE_CONFIG__VCSEL_PERIOD_A));
    uint32_t range_us = timeoutMclksToMicroseconds(decodeTimeout(readReg16Bit(RANGE_CONFIG__TIMEOUT_MACROP_A)), macro);
    return 2 * range_us + TimingGuard;
}

// STSW-IMG009 ULD ROI API; UM2555 documents the SPAD locations.
void VL53L1X::setROISize(uint8_t width, uint8_t height) {
    if (width > 16) width = 16;
    if (height > 16) height = 16;
    if (width > 10 || height > 10) writeReg(ROI_CONFIG__USER_ROI_CENTRE_SPAD, 199);
    writeReg(ROI_CONFIG__USER_ROI_REQUESTED_GLOBAL_XY_SIZE, (height - 1) << 4 | (width - 1));
}
void VL53L1X::getROISize(uint8_t *width, uint8_t *height) {
    uint8_t v = readReg(ROI_CONFIG__USER_ROI_REQUESTED_GLOBAL_XY_SIZE);
    *width = (v & 0xF) + 1;
    *height = (v >> 4) + 1;
}
void VL53L1X::setROICenter(uint8_t spad) { writeReg(ROI_CONFIG__USER_ROI_CENTRE_SPAD, spad); }
uint8_t VL53L1X::getROICenter() { return readReg(ROI_CONFIG__USER_ROI_CENTRE_SPAD); }
void VL53L1X::startContinuous(uint32_t period_ms) {
    writeReg32Bit(SYSTEM__INTERMEASUREMENT_PERIOD, period_ms * osc_calibrate_val);
    writeReg(SYSTEM__INTERRUPT_CLEAR, 1);
    writeReg(SYSTEM__MODE_START, 0x40);
}
void VL53L1X::stopContinuous() {
    writeReg(SYSTEM__MODE_START, 0x80);
    calibrated = false;
    if (saved_vhv_init != 0) writeReg(VHV_CONFIG__INIT, saved_vhv_init);
    if (saved_vhv_timeout != 0) writeReg(VHV_CONFIG__TIMEOUT_MACROP_LOOP_BOUND, saved_vhv_timeout);
    writeReg(PHASECAL_CONFIG__OVERRIDE, 0);
}
uint16_t VL53L1X::read(bool blocking) {
    if (blocking) {
        startTimeout();
        while (!dataReady()) {
            if (checkTimeoutExpired()) { did_timeout = true; return 0; }
        }
    }
    readResults();
    if (last_status != ESP_OK) { ranging_data.range_status = None; return 0; }
    if (!calibrated) {
        setupManualCalibration();
        calibrated = true;
    }
    updateDSS();
    getRangingData();
    writeReg(SYSTEM__INTERRUPT_CLEAR, 1);
    if (last_status != ESP_OK) { ranging_data.range_status = None; return 0; }
    return ranging_data.range_mm;
}
uint16_t VL53L1X::readSingle(bool blocking) {
    writeReg(SYSTEM__INTERRUPT_CLEAR, 1);
    writeReg(SYSTEM__MODE_START, 0x10);
    return blocking ? read(true) : 0;
}
const char *VL53L1X::rangeStatusToString(RangeStatus status) {
    switch (status) {
    case RangeValid: return "range valid";
    case SigmaFail: return "sigma fail";
    case SignalFail: return "signal fail";
    case RangeValidMinRangeClipped: return "range valid, min range clipped";
    case OutOfBoundsFail: return "out of bounds fail";
    case HardwareFail: return "hardware fail";
    case RangeValidNoWrapCheckFail: return "range valid, no wrap check fail";
    case WrapTargetFail: return "wrap target fail";
    case XtalkSignalFail: return "xtalk signal fail";
    case SynchronizationInt: return "synchronization int";
    case MinRangeFail: return "min range fail";
    case None: return "no update";
    default: return "unknown status";
    }
}
bool VL53L1X::timeoutOccurred() {
    bool value = did_timeout;
    did_timeout = false;
    return value;
}

// VL53L1_low_power_auto_setup_manual_calibration.
void VL53L1X::setupManualCalibration() {
    saved_vhv_init = readReg(VHV_CONFIG__INIT);
    saved_vhv_timeout = readReg(VHV_CONFIG__TIMEOUT_MACROP_LOOP_BOUND);
    writeReg(VHV_CONFIG__INIT, saved_vhv_init & 0x7F);
    writeReg(VHV_CONFIG__TIMEOUT_MACROP_LOOP_BOUND, (saved_vhv_timeout & 3) + (3 << 2));
    writeReg(PHASECAL_CONFIG__OVERRIDE, 1);
    writeReg(CAL_CONFIG__VCSEL_START, readReg(PHASECAL_RESULT__VCSEL_START));
}
void VL53L1X::readResults() {
    uint8_t b[17] = {};
    if (!readBytes(RESULT__RANGE_STATUS, b, sizeof b)) return;
    results.range_status = b[0];
    results.stream_count = b[2];
    results.dss_actual_effective_spads_sd0 = static_cast<uint16_t>(b[3]) << 8 | b[4];
    results.ambient_count_rate_mcps_sd0 = static_cast<uint16_t>(b[7]) << 8 | b[8];
    results.final_crosstalk_corrected_range_mm_sd0 = static_cast<uint16_t>(b[13]) << 8 | b[14];
    results.peak_signal_count_rate_crosstalk_corrected_mcps_sd0 = static_cast<uint16_t>(b[15]) << 8 | b[16];
}
// VL53L1_low_power_auto_update_DSS, including divide-by-zero fallback.
void VL53L1X::updateDSS() {
    uint16_t spads = results.dss_actual_effective_spads_sd0;
    if (spads != 0) {
        uint32_t rate = static_cast<uint32_t>(results.peak_signal_count_rate_crosstalk_corrected_mcps_sd0) +
                        results.ambient_count_rate_mcps_sd0;
        if (rate > 0xFFFF) rate = 0xFFFF;
        rate <<= 16;
        rate /= spads;
        if (rate != 0) {
            uint32_t required = (static_cast<uint32_t>(TargetRate) << 16) / rate;
            if (required > 0xFFFF) required = 0xFFFF;
            writeReg16Bit(DSS_CONFIG__MANUAL_EFFECTIVE_SPADS_SELECT, required);
            return;
        }
    }
    writeReg16Bit(DSS_CONFIG__MANUAL_EFFECTIVE_SPADS_SELECT, 0x8000);
}
// VL53L1_GetRangingMeasurementData gain correction and ConvertStatusLite.
void VL53L1X::getRangingData() {
    uint16_t range = results.final_crosstalk_corrected_range_mm_sd0;
    ranging_data.range_mm = (static_cast<uint32_t>(range) * 2011 + 0x0400) / 0x0800;
    switch (results.range_status) {
    case 17:
    case 2:
    case 1:
    case 3: ranging_data.range_status = HardwareFail; break;
    case 13: ranging_data.range_status = MinRangeFail; break;
    case 18: ranging_data.range_status = SynchronizationInt; break;
    case 5: ranging_data.range_status = OutOfBoundsFail; break;
    case 4: ranging_data.range_status = SignalFail; break;
    case 6: ranging_data.range_status = SigmaFail; break;
    case 7: ranging_data.range_status = WrapTargetFail; break;
    case 12: ranging_data.range_status = XtalkSignalFail; break;
    case 8: ranging_data.range_status = RangeValidMinRangeClipped; break;
    case 9: ranging_data.range_status = results.stream_count == 0 ? RangeValidNoWrapCheckFail : RangeValid; break;
    default: ranging_data.range_status = None;
    }
    ranging_data.peak_signal_count_rate_MCPS = countRateFixedToFloat(results.peak_signal_count_rate_crosstalk_corrected_mcps_sd0);
    ranging_data.ambient_count_rate_MCPS = countRateFixedToFloat(results.ambient_count_rate_mcps_sd0);
}
uint32_t VL53L1X::decodeTimeout(uint16_t v) { return (static_cast<uint32_t>(v & 0xFF) << (v >> 8)) + 1; }
uint16_t VL53L1X::encodeTimeout(uint32_t mclks) {
    uint32_t ls = 0;
    uint16_t ms = 0;
    if (mclks == 0) return 0;
    ls = mclks - 1;
    while ((ls & 0xFFFFFF00) > 0) {
        ls >>= 1;
        ++ms;
    }
    return (ms << 8) | (ls & 0xFF);
}
uint32_t VL53L1X::timeoutMclksToMicroseconds(uint32_t clocks, uint32_t macro) {
    return (static_cast<uint64_t>(clocks) * macro + 0x800) >> 12;
}
uint32_t VL53L1X::timeoutMicrosecondsToMclks(uint32_t us, uint32_t macro) {
    return ((us << 12) + (macro >> 1)) / macro;
}
uint32_t VL53L1X::calcMacroPeriod(uint8_t vcsel) {
    uint32_t pll = (static_cast<uint32_t>(1) << 30) / fast_osc_frequency;
    uint8_t pclks = (vcsel + 1) << 1;
    uint32_t macro = 2304 * pll;
    macro >>= 6;
    macro *= pclks;
    macro >>= 6;
    return macro;
}
