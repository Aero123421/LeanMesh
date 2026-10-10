#include "field_presence.h"
#ifndef FIELD_TOF
#define FIELD_TOF 0
#endif
#if FIELD_TOF
#include <kguard_field/presence_v2.hpp>
#include <algorithm>

namespace {
namespace pv = kguard::field::presence_v2;
pv::Config configuration() {
    pv::Config c;
    c.no_sample_fault_ms = 10000;
    return c;
}
pv::Detector detector(configuration());
bool enabled, ready, have_sample, last_valid, no_sensor_request;
bool reevaluation_required;
uint64_t detector_ms, failure_ms;
uint64_t sample_ms;
uint16_t distance;
uint32_t learn_request;
}

void field_presence_begin(bool use_sensor, uint64_t now) {
    enabled = use_sensor;
    ready = have_sample = last_valid = no_sensor_request = false;
    learn_request = 0;
    sample_ms = 0;
    distance = UINT16_MAX;
    reevaluation_required = false;
    detector_ms = now;
    failure_ms = 0;
    detector = pv::Detector(configuration());
    // This is a private detector generation, not an SDK assignment generation.
    if (enabled) detector.begin(now, 1, nullptr);
}
void field_presence_ready(bool value) { ready = enabled && value; }
bool field_presence_learn(uint64_t now) {
    if (!enabled) {
        no_sensor_request = true;
        return false;
    }
    if (now < detector_ms || detector.learn_state() == pv::LearnState::Running || learn_request == UINT32_MAX) return false;
    if (!detector.learn(now, learn_request + 1)) return false;
    detector_ms = now;
    ++learn_request;
    return true;
}
void field_presence_sample(uint64_t now, uint16_t mm, uint8_t status) {
    if (!enabled || now < detector_ms) return;
    detector.update(now, mm, status);
    detector_ms = now;
    if (reevaluation_required && now > failure_ms) reevaluation_required = false;
    have_sample = true;
    sample_ms = now;
    last_valid = status == 0 && mm >= 100 && mm <= 4000;
    distance = last_valid ? mm : UINT16_MAX;
    // This kit does not publish KG transitions; acknowledge the bounded detector ring.
    if (detector.pending() != 0) detector.ack(detector.transition(detector.pending() - 1)->n);
}
void field_presence_tick(uint64_t now) {
    if (!enabled || now < detector_ms) return;
    const pv::LearnState before = detector.learn_state();
    detector.tick(now);
    detector_ms = now;
    if (before == pv::LearnState::Running && detector.learn_state() == pv::LearnState::Failed) {
        // KG timeout clears doubt but has not classified a post-timeout sample.
        // Preserve the old background without exposing its former held vacant.
        reevaluation_required = true;
        failure_ms = now;
    }
}
void field_presence_capture(uint64_t now, field_presence_snapshot_t *out) {
    *out = {};
    out->capture_ms = static_cast<uint32_t>(now);
    out->presence = enabled ? (ready ? static_cast<uint8_t>(detector.state()) + 1 : FIELD_PRESENCE_UNKNOWN)
                            : FIELD_PRESENCE_DISABLED;
    // Current observation must not masquerade as vacant during silence. The
    // exact detector retains held() and its 10s no-response latch separately.
    if (enabled && (reevaluation_required || !have_sample || now - sample_ms >= 1000)) out->presence = FIELD_PRESENCE_UNKNOWN;
    out->learning = no_sensor_request ? static_cast<uint8_t>(FIELD_LEARN_NO_SENSOR) : static_cast<uint8_t>(detector.learn_state());
    out->flags = ready ? FIELD_SENSOR_READY : 0;
    out->sample_age_ms = have_sample ? static_cast<uint16_t>(std::min<uint64_t>(now - sample_ms, 65534)) : UINT16_MAX;
    out->distance_mm = ready && last_valid && have_sample && now - sample_ms < 80 ? distance : UINT16_MAX;
    out->background_mm = enabled && detector.has_background() ? detector.background().distance_mm : UINT16_MAX;
    if (enabled && detector.has_background()) {
        out->flags |= FIELD_BACKGROUND_VALID;
        out->noise_mm = detector.background().noise_mm;
    }
    out->learn_request = learn_request;
    if (enabled) out->fault_bits = (detector.sensor_fault() ? 1u : 0u) |
        (detector.background_fault() ? 2u : 0u) | (detector.learn_fault() ? 4u : 0u);
}
#else
// Sensor-free display: no detector header, sample/transition ring, or driver.
namespace {
bool no_sensor_request;
}
void field_presence_begin(bool, uint64_t) { no_sensor_request = false; }
void field_presence_ready(bool) {}
bool field_presence_learn(uint64_t) {
    no_sensor_request = true;
    return false;
}
void field_presence_sample(uint64_t, uint16_t, uint8_t) {}
void field_presence_tick(uint64_t) {}
void field_presence_capture(uint64_t now, field_presence_snapshot_t *out) {
    *out = {};
    out->presence = FIELD_PRESENCE_DISABLED;
    out->learning = no_sensor_request ? FIELD_LEARN_NO_SENSOR : FIELD_LEARN_IDLE;
    out->capture_ms = static_cast<uint32_t>(now);
    out->sample_age_ms = out->distance_mm = out->background_mm = UINT16_MAX;
}
#endif
