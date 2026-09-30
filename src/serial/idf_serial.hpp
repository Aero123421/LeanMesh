// USB-Serial/JTAG transport of the root (ESP-IDF, docs/19): the ByteStream of RootUsb. One task
// blocks in the driver (a wait, not a poll), copies received bytes into a bounded ring and wakes
// the mesh owner, which drains the ring inside its step. Nothing else runs in that task: framing,
// AEAD and EDHOC stay on the owner and the slow-job worker.
//
// The port carries the binary protocol, so the console must not share it (a root product build sets
// CONFIG_ESP_CONSOLE_NONE or moves the console to UART); log text on this port would only be noise
// for the COBS resync, but it would leak state to whoever holds the cable.
#pragma once

#include <cstdint>

#include "core/engine.hpp"
#include "core/status.hpp"

namespace lm::idf {
class IdfOwner;
}

namespace lm::serial {

// Installs the driver, creates the port task and the RootUsb adapter and attaches it to `engine`.
// Root builds only. A failure leaves the mesh running without USB (the link stays down).
[[nodiscard]] Status idf_root_serial_start(Engine &engine, idf::IdfOwner &owner);
void idf_root_serial_stop();

} // namespace lm::serial
