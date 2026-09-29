#include "root/groups.hpp"

#include <algorithm>

#include "core/engine.hpp"

namespace lm::root {
Status Groups::set(const group::SetRequest &rq) {
    Ledger &led = engine_.ledger();
    if (engine_.config().role != Role::Root) {
        return Status::RoleNotAllowed;
    }
    if (!led.ready()) {
        return Status::Busy; // the ledger is still loading: no member is known yet
    }
    if (rq.group_id == 0 || rq.count > group::k_max_targets || (rq.members == nullptr && rq.count != 0)) {
        return Status::InvalidArgument;
    }
    Group *g = nullptr;
    Group *free_slot = nullptr;
    for (Group &x : groups_) {
        if (x.id == rq.group_id) {
            g = &x;
        } else if (x.id == 0 && free_slot == nullptr) {
            free_slot = &x;
        }
    }
    const uint64_t current = g != nullptr ? g->revision : 0;
    if (rq.expected_revision != current) {
        return Status::Conflict;
    }
    if (g == nullptr && (g = free_slot) == nullptr) {
        return Status::NoCapacity;
    }
    if (current >= k_u63_max) {
        return Status::RecoveryRequired;
    }
    std::array<uint8_t, group::k_max_targets> slots{};
    for (std::size_t i = 0; i < rq.count; ++i) {
        DeviceId d;
        std::copy(rq.members + i * rq.stride, rq.members + i * rq.stride + 32, d.bytes.begin());
        const Entry *e = led.find(d);
        if (e == nullptr || e->state != EntryState::Active) {
            return Status::NotFound; // only a member of this domain can be in a group
        }
        slots[i] = static_cast<uint8_t>(e->address.value() - 2);
        for (std::size_t j = 0; j < i; ++j) {
            if (slots[j] == slots[i]) {
                return Status::InvalidArgument;
            }
        }
    }
    g->id = rq.group_id;
    g->revision = current + 1;
    g->count = static_cast<uint8_t>(rq.count);
    g->slot = slots;
    return Status::Ok;
}

Status Groups::snapshot(uint32_t group_id, uint64_t revision, group::Op &out, DeviceId *ids) const {
    const Group *g = nullptr;
    for (const Group &x : groups_) {
        g = x.id == group_id && x.id != 0 ? &x : g;
    }
    if (g == nullptr) {
        return Status::NotFound;
    }
    if (g->revision != revision) {
        return Status::Conflict;
    }
    const Ledger &led = engine_.ledger();
    out.total = g->count;
    for (std::size_t i = 0; i < g->count; ++i) { // insertion sort by DeviceId: the snapshot is sorted
        const Entry &e = led.entry(g->slot[i]);
        if (e.state == EntryState::Free) {
            return Status::NotFound; // the slot holds no device any more: nothing to name (a left member stays, and is rejected at dispatch)
        }
        group::Target t;
        t.assignment = e.assignment;
        t.membership = e.membership;
        std::size_t j = i;
        for (; j > 0 && e.device < ids[j - 1]; --j) {
            out.t[j] = out.t[j - 1];
            ids[j] = ids[j - 1];
        }
        out.t[j] = t;
        ids[j] = e.device;
    }
    return Status::Ok;
}

bool Groups::current(const DeviceId &d, uint64_t assignment, uint64_t membership) const {
    const Entry *e = engine_.ledger().find(d);
    return e != nullptr && e->state == EntryState::Active && e->assignment == assignment && e->membership == membership;
}

bool Groups::allowed(const DeviceId &d) const {
    const Entry *e = engine_.ledger().find(d);
    return e == nullptr || e->state == EntryState::Active; // the ledger may only deny (S8-D7: factory members)
}

} // namespace lm::root
