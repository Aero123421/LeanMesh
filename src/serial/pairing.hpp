// The sealed "paired host" record of the root (decision D6, docs/IMPLEMENTATION.md): exactly one
// Host DeviceId is allowed to open the USB session. It is installed at provisioning (never over
// the serial port itself), read by the root at start, and compared with the DeviceId inside the
// fleet-signed DeviceCredential the Host presents. No shared USB secret exists.
#pragma once

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/ports.hpp"
#include "core/status.hpp"

namespace lm::serial {

// Record id in the store key space (src/store/record.hpp lists ids 1..11 today; this one is
// reserved here so the two slices do not edit the same header, decision S10-D2).
inline constexpr uint16_t k_rec_paired_host = 0x0040;
inline constexpr uint8_t k_paired_state_active = 1;

// Provisioning/test path (sim provisioning, factory tool): commits the record through the sealed
// 2-slot record layer. Flash I/O: worker job or provisioning context only.
[[nodiscard]] Status write_paired_host(port::Store &store, const DeviceId &host);

} // namespace lm::serial
