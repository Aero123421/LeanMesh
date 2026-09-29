// Root side of groups (docs/10 §group構成, docs/22 §2): the registry of group definitions. A group is a
// revision and up to 64 members kept as ledger slots (no DeviceId copies: the ledger is the only
// identity table, ADR-002); a snapshot copies what it needs (DeviceId and generations) and stands on that.
// The registry is RAM only: the Host holds the definitions and sets them again
// after a root restart (revisions start over at 1); a snapshot is taken from it when an operation starts
// or a member origin asks for one, and the snapshot then stands on its own generations.
#pragma once

#include <array>
#include <cstdint>
#include <type_traits>

#include "core/group/group.hpp"
#include "core/profile.hpp"

namespace lm {
class Engine;
}

namespace lm::root {

inline constexpr std::size_t k_groups = 8;

class Groups {
  public:
    explicit Groups(Engine &engine) : engine_(engine) {}
    Groups(const Groups &) = delete;
    Groups &operator=(const Groups &) = delete;

    void stop() { groups_ = {}; }
    // Replaces the members of `group_id` if `expected_revision` is its current one (0: it does not
    // exist yet); the new revision is expected + 1. Members must be ACTIVE in the ledger.
    [[nodiscard]] Status set(const group::SetRequest &rq);
    // Fills `out.t` (sorted by DeviceId), `ids` (the same order, k_max_targets entries), `total` and the generations
    // of the members now. NotFound: no such group. Conflict: `revision` is not the current one.
    [[nodiscard]] Status snapshot(uint32_t group_id, uint64_t revision, group::Op &out, DeviceId *ids) const;
    // The device is still an ACTIVE member with exactly the snapshot's generations.
    [[nodiscard]] bool current(const DeviceId &d, uint64_t assignment, uint64_t membership) const;
    // May `d` ask for a snapshot? The ledger only denies: a factory-provisioned member has no entry (S8-D7).
    [[nodiscard]] bool allowed(const DeviceId &d) const;

  private:
    struct Group {
        uint32_t id = 0; // 0: free
        uint8_t count = 0;
        uint64_t revision = 0;
        std::array<uint8_t, group::k_max_targets> slot{};
    };
    Engine &engine_;
    std::array<Group, k_groups> groups_{};
};

// Leaf/relay builds carry no registry.
struct NoGroups {
    explicit NoGroups(Engine &) {}
    void stop() {}
    [[nodiscard]] Status set(const group::SetRequest &) { return Status::RoleNotAllowed; }
    [[nodiscard]] Status snapshot(uint32_t, uint64_t, group::Op &, DeviceId *) const { return Status::Unsupported; }
    [[nodiscard]] bool current(const DeviceId &, uint64_t, uint64_t) const { return false; }
    [[nodiscard]] bool allowed(const DeviceId &) const { return false; }
};

using GroupsType = std::conditional_t<k_root_capable, Groups, NoGroups>;

} // namespace lm::root
