// The sealed "paired host" record of the root (decision D6, docs/IMPLEMENTATION.md): exactly one
// Host DeviceId is allowed to open the USB session. It is installed at provisioning (never over
// the serial port itself), read by the root at start, and compared with the DeviceId inside the
// fleet-signed DeviceCredential the Host presents. No shared USB secret exists.
#pragma once

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/ports.hpp"
#include "core/status.hpp"
#include "store/record.hpp"

namespace lm::serial {

// Record id in the store key space (decision S10-D2, folded into store::rec: 0x40 collided with the
// assignment-ticket record). The identity load job reads it on root-capable builds.
inline constexpr uint16_t k_rec_paired_host = store::rec::paired_host;
inline constexpr uint8_t k_paired_state_active = store::k_paired_host_active;

// Provisioning/test path (sim provisioning, factory tool): commits the record through the sealed
// 2-slot record layer. Flash I/O: worker job or provisioning context only.
[[nodiscard]] Status write_paired_host(port::Store &store, const DeviceId &host);

} // namespace lm::serial
