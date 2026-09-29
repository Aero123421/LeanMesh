// Sim/bench-only provisioning: writes the sealed identity records a device would carry from the
// factory into a SimStore, through the same record layer the firmware reads them with. Not a
// production path and not part of any firmware build (docs/21 §9: no factory reset via SDK).
#pragma once

#include "core/bytes.hpp"
#include "core/member/credentials.hpp"
#include "core/ports.hpp"

namespace lm::sim {

struct ProvisionInput {
    ByteView scalar32;      // device private key (identity record)
    ByteView device_cose;   // fleet-signed DeviceCredential
    member::TrustAnchor trust;
    ByteView delegation_cose; // empty: identity only
    ByteView member_cose;     // empty: not a member
    const member::Floors *floors = nullptr;
    // A root of a NEW network: its empty ledger (manifest bound to this domain, SEC-D5). The only path that
    // creates a ledger; a root that later finds none is RECOVERY_REQUIRED.
    const DomainId *new_ledger_domain = nullptr;
};

// Durable when Ok (each record committed and read back by the record layer).
[[nodiscard]] Status provision_store(port::Store &store, const ProvisionInput &in);

} // namespace lm::sim
