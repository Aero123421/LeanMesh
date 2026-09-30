// Root side of groups (docs/10 §group構成, docs/22 §2): the registry of group definitions. A group is a
// revision and up to 64 members kept as ledger slots (no DeviceId copies: the ledger is the only
// identity table, ADR-002); a snapshot copies what it needs (DeviceId and generations) and stands on that.
//
// FIX8-D9 (second review #2): a slot is a device only while the ledger does not give it to another one, so a slot a
// definition names is never reused (Ledger::reusable): a departed member stays named - and rejected at dispatch - until
// the Host edits the group, instead of its successor in the slot silently becoming the target.
// FIX8-D10 (second review #9, api/SEMANTICS.md "durable commit"): the registry is one sealed record
// (store::rec::root_groups). A set is applied to RAM and reported (LM_EVENT_OPERATION) only once that record is
// durable; one set is committed at a time (the next is BUSY meanwhile). The ledger's load restores it before any group operation
// or join runs; revisions go on across restarts. A commit whose result is unknown leaves the registry refusing
// (RECOVERY_REQUIRED, every slot kept) until the stored record is read again at the next start.
#pragma once

#include <array>
#include <cstdint>
#include <type_traits>

#include "core/group/group.hpp"
#include "core/profile.hpp"
#include "core/time.hpp"

namespace lm {
class Engine;
}

namespace lm::root {

inline constexpr std::size_t k_groups = 8;
// store::rec::root_groups: version u8 (1) | n u8 | n x (group id u32 | revision u64 | count u8 | count x slot u8)
// (a ledger slot per member; at most 2 + 8 x 77 = 618 B, one record).
inline constexpr uint8_t k_groups_record_version = 1;

class Groups {
  public:
    explicit Groups(Engine &engine) : engine_(engine) {}
    Groups(const Groups &) = delete;
    Groups &operator=(const Groups &) = delete;

    void stop();
    // Replaces the members of `group_id` if `expected_revision` is its current one (0: it does not exist yet); the new
    // revision is expected + 1. Members must be ACTIVE in the ledger. Ok: accepted as `operation` (a new control
    // operation id), which ends with LM_EVENT_OPERATION once the definition is durable.
    [[nodiscard]] Status set(const group::SetRequest &rq, uint64_t &operation, MonoTime now);
    // Fills `out.t` (sorted by DeviceId), `ids` (the same order, k_max_targets entries), `total` and the generations
    // of the members now. NotFound: no such group. Conflict: `revision` is not the current one.
    [[nodiscard]] Status snapshot(uint32_t group_id, uint64_t revision, group::Op &out, DeviceId *ids) const;
    // The device is still an ACTIVE member with exactly the snapshot's generations.
    [[nodiscard]] bool current(const DeviceId &d, uint64_t assignment, uint64_t membership) const;
    // May `d` ask for a snapshot? The ledger only denies: a factory-provisioned member has no entry (S8-D7).
    [[nodiscard]] bool allowed(const DeviceId &d) const;
    // FIX8-D9: a definition (committed or being committed) names ledger slot `slot`. True for every slot while the
    // registry is not known (before the load, or in doubt).
    [[nodiscard]] bool names_slot(std::size_t slot) const;

    // ---- the ledger's plumbing (its load and its maintenance commit the record) ----
    // `load`: the record's load status; `payload`: its bytes when Ok. Ledger entries are loaded already.
    void restore(Status load, ByteView payload);
    // The registry with the change being committed, as the record payload.
    [[nodiscard]] Status encode(MutByteView out, std::size_t &len) const;
    void committed(Status s);

  private:
    struct Group {
        uint32_t id = 0; // 0: free
        uint8_t count = 0;
        uint64_t revision = 0;
        std::array<uint8_t, group::k_max_targets> slot{};
    };
    enum class St : uint8_t { Unloaded, Ready, Doubt };
    [[nodiscard]] Status usable() const;
    Engine &engine_;
    std::array<Group, k_groups> groups_{};
    St st_ = St::Unloaded;
    Group staged_;             // the definition being committed, for groups_[pending_index_]
    std::size_t pending_index_ = 0;
    uint64_t pending_op_ = 0;
    bool pending_ = false;
};

// Leaf/relay builds carry no registry.
struct NoGroups {
    explicit NoGroups(Engine &) {}
    void stop() {}
    [[nodiscard]] Status set(const group::SetRequest &, uint64_t &, MonoTime) { return Status::RoleNotAllowed; }
    [[nodiscard]] Status snapshot(uint32_t, uint64_t, group::Op &, DeviceId *) const { return Status::Unsupported; }
    [[nodiscard]] bool current(const DeviceId &, uint64_t, uint64_t) const { return false; }
    [[nodiscard]] bool allowed(const DeviceId &) const { return false; }
    [[nodiscard]] bool names_slot(std::size_t) const { return false; }
};

using GroupsType = std::conditional_t<k_root_capable, Groups, NoGroups>;

} // namespace lm::root
