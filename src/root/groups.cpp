#include "root/groups.hpp"

#include <algorithm>

#include "core/codec.hpp"
#include "core/engine.hpp"

namespace lm::root {

void Groups::stop() {
    if (pending_) { // the stop cuts its commit: durable or not, the next start reads the registry (INDETERMINATE)
        engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(Status::RecoveryRequired), pending_op_, nullptr);
    }
    groups_ = {};
    st_ = St::Unloaded; // the next load restores the stored registry
    pending_ = false;
}

Status Groups::usable() const {
    if (st_ == St::Doubt || engine_.ledger().failed()) {
        return Status::RecoveryRequired;
    }
    return st_ == St::Ready && engine_.ledger().ready() ? Status::Ok : Status::Busy; // before the load: no member known
}

Status Groups::set(const group::SetRequest &rq, uint64_t &operation, MonoTime now) {
    if (engine_.config().role != Role::Root) {
        return Status::RoleNotAllowed; // (and a node of another role holds no ledger: P8)
    }
    if ((engine_.identity().delegation().permissions & member::k_perm_groups) == 0) {
        return Status::AuthRejected; // FIX12-D2: this root's delegation carries no groups permission
    }
    LM_TRY(usable());
    if (pending_) {
        return Status::Busy; // one definition is committed at a time (FIX8-D10)
    }
    Ledger &led = engine_.ledger();
    if (rq.group_id == 0 || rq.count > group::k_max_targets || (rq.members == nullptr && rq.count != 0)) {
        return Status::InvalidArgument;
    }
    std::size_t index = k_groups;
    std::size_t free_index = k_groups;
    for (std::size_t i = 0; i < groups_.size(); ++i) {
        if (groups_[i].id == rq.group_id) {
            index = i;
        } else if (groups_[i].id == 0 && free_index == k_groups) {
            free_index = i;
        }
    }
    const uint64_t current = index != k_groups ? groups_[index].revision : 0;
    if (rq.expected_revision != current) {
        return Status::Conflict;
    }
    if (index == k_groups && (index = free_index) == k_groups) {
        return Status::NoCapacity;
    }
    if (current >= k_u63_max) {
        return Status::RecoveryRequired;
    }
    Group g;
    for (std::size_t i = 0; i < rq.count; ++i) {
        DeviceId d;
        std::copy(rq.members + i * rq.stride, rq.members + i * rq.stride + 32, d.bytes.begin());
        const Entry *e = led.authorized(d); // FIX5-D2: ACTIVE and above every floor
        if (e == nullptr) {
            return Status::NotFound; // only a member of this domain can be in a group
        }
        g.slot[i] = static_cast<uint8_t>(e->address.value() - 2);
        for (std::size_t j = 0; j < i; ++j) {
            if (g.slot[j] == g.slot[i]) {
                return Status::InvalidArgument;
            }
        }
    }
    g.id = rq.group_id;
    g.revision = current + 1;
    g.count = static_cast<uint8_t>(rq.count);
    staged_ = g;
    pending_index_ = index;
    pending_op_ = engine_.next_control_op();
    pending_ = true;
    operation = pending_op_;
    led.want_groups_commit(now); // applied and reported by committed()
    return Status::Ok;
}

// The registry as it is once the pending definition is in (store::rec::root_groups, layout in groups.hpp).
Status Groups::encode(MutByteView out, std::size_t &len) const {
    Writer w{out};
    std::size_t n = 0;
    for (std::size_t i = 0; i < groups_.size(); ++i) {
        n += (pending_ && i == pending_index_ ? staged_.id : groups_[i].id) != 0 ? 1 : 0;
    }
    w.u8(k_groups_record_version);
    w.u8(static_cast<uint8_t>(n));
    for (std::size_t i = 0; i < groups_.size(); ++i) {
        const Group &g = pending_ && i == pending_index_ ? staged_ : groups_[i];
        if (g.id == 0) {
            continue;
        }
        w.u32be(g.id);
        w.u64be(g.revision);
        w.u8(g.count);
        w.bytes(ByteView{g.slot.data(), g.count});
    }
    len = w.size();
    return w.finish();
}

void Groups::committed(Status s) {
    if (!pending_) {
        return;
    }
    pending_ = false;
    if (s == Status::Ok) {
        groups_[pending_index_] = staged_;
    } else {
        st_ = St::Doubt; // the record may hold the new definition or the old one: nothing is served until re-read
    }
    engine_.emit_event(LM_EVENT_OPERATION, s == Status::Ok ? 0U : static_cast<uint32_t>(Status::RecoveryRequired),
                       pending_op_, nullptr);
}

// A record that does not decode, or names a slot the ledger does not hold, is never "no groups": the registry stays in
// doubt (RECOVERY_REQUIRED, every slot kept) and the Host sets the groups again once the root is recovered.
void Groups::restore(Status load, ByteView payload) {
    groups_ = {};
    pending_ = false;
    st_ = St::Doubt;
    if (load == Status::NotFound) {
        st_ = St::Ready;
        return;
    }
    if (load != Status::Ok) {
        return;
    }
    Reader r{payload};
    const uint8_t version = r.u8();
    const uint8_t n = r.u8();
    if (!r.ok() || version != k_groups_record_version || n > k_groups) {
        return;
    }
    std::array<Group, k_groups> gs{};
    const Ledger &led = engine_.ledger();
    for (std::size_t i = 0; i < n; ++i) {
        Group &g = gs[i];
        g.id = r.u32be();
        g.revision = r.u64be();
        g.count = r.u8();
        if (!r.ok() || g.id == 0 || g.revision == 0 || g.revision > k_u63_max || g.count > group::k_max_targets) {
            return;
        }
        const ByteView slots = r.bytes(g.count);
        std::copy(slots.begin(), slots.end(), g.slot.begin());
        for (std::size_t k = 0; k < g.count && r.ok(); ++k) {
            if (g.slot[k] >= k_ledger_slots || led.entry(g.slot[k]).state == EntryState::Free ||
                std::count(g.slot.begin(), g.slot.begin() + g.count, g.slot[k]) != 1) {
                return;
            }
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (gs[j].id == g.id) {
                return;
            }
        }
    }
    if (r.finish() != Status::Ok) {
        return;
    }
    groups_ = gs;
    st_ = St::Ready;
}

Status Groups::snapshot(uint32_t group_id, uint64_t revision, group::Op &out, DeviceId *ids) const {
    LM_TRY(usable());
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
            return Status::NotFound; // (never: a named slot is not reused; a left member stays, rejected at dispatch)
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
    const Entry *e = engine_.ledger().authorized(d); // FIX5-D2
    return e != nullptr && e->assignment == assignment && e->membership == membership;
}

bool Groups::allowed(const DeviceId &d) const {
    const Ledger &led = engine_.ledger();
    const Entry *e = led.find(d);
    return e == nullptr || led.authorizes(*e); // the ledger may only deny (S8-D7: factory members); FIX5-D2: floors too
}

bool Groups::names_slot(std::size_t slot) const {
    if (st_ != St::Ready) {
        return true; // unknown what is named: nothing is reused (fail closed)
    }
    const auto names = [slot](const Group &g) {
        return g.id != 0 && std::find(g.slot.begin(), g.slot.begin() + g.count, slot) != g.slot.begin() + g.count;
    };
    return std::any_of(groups_.begin(), groups_.end(), names) || (pending_ && names(staged_));
}

} // namespace lm::root
