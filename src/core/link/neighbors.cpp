#include "core/link/neighbors.hpp"

namespace lm::link {
namespace {

bool live(const SessionKeys &s, MonoTime now) { return s.active && now < s.valid_until; }

} // namespace

Neighbor *Neighbors::find_device(const DeviceId &d) {
    Neighbor *found = nullptr;
    table_.for_each([&](Handle, Neighbor &n) {
        if (n.device == d && !n.join_only) {
            found = &n;
        }
    });
    return found;
}

Neighbor *Neighbors::find_join(const DeviceId &d) {
    Neighbor *found = nullptr;
    table_.for_each([&](Handle, Neighbor &n) {
        if (n.device == d && n.join_only) {
            found = &n;
        }
    });
    return found;
}

const Neighbor *Neighbors::find_device(const DeviceId &d) const {
    return const_cast<Neighbors *>(this)->find_device(d);
}

Neighbor *Neighbors::find_mac(const MacAddr &m) {
    Neighbor *found = nullptr;
    table_.for_each([&](Handle, Neighbor &n) {
        if (n.mac == m && !n.join_only) {
            found = &n;
        }
    });
    return found;
}

Neighbor *Neighbors::by_rx_sid(const MacAddr &mac, uint32_t sid, SessionKeys *&which) {
    Neighbor *found = nullptr;
    table_.for_each([&](Handle, Neighbor &n) {
        if (n.mac != mac) {
            return;
        }
        if (n.cur.active && n.cur.rx_sid == sid) {
            found = &n;
            which = &n.cur;
        } else if (n.prev.active && n.prev.rx_sid == sid) {
            found = &n;
            which = &n.prev;
        }
    });
    return found;
}

Neighbor *Neighbors::by_tx_sid(const MacAddr &mac, uint32_t sid) {
    Neighbor *found = nullptr;
    table_.for_each([&](Handle, Neighbor &n) {
        if (n.mac == mac && n.cur.active && n.cur.tx_sid == sid) {
            found = &n;
        }
    });
    return found;
}

bool Neighbors::sid_in_use(uint32_t sid) const {
    bool used = false;
    const_cast<Table &>(table_).for_each([&](Handle, Neighbor &n) {
        used = used || (n.cur.active && n.cur.rx_sid == sid) || (n.prev.active && n.prev.rx_sid == sid);
    });
    return used;
}

Neighbor *Neighbors::acquire() {
    const Handle h = table_.acquire();
    return h.is_none() ? nullptr : table_.get(h);
}

void Neighbors::remove(Neighbor &n) {
    Handle target = Handle::none();
    table_.for_each([&](Handle h, Neighbor &item) {
        if (&item == &n) {
            target = h;
        }
    });
    n.cur.wipe();
    n.prev.wipe();
    (void)table_.release(target);
}

std::size_t Neighbors::sweep(MonoTime now, PeerHandle *released, std::size_t cap) {
    std::size_t n_released = 0;
    Neighbor *dead[k_max_neighbors];
    std::size_t n_dead = 0;
    table_.for_each([&](Handle, Neighbor &n) {
        if (n.prev.active && !live(n.prev, now)) {
            n.prev.wipe();
        }
        if (n.cur.active && !live(n.cur, now)) {
            n.cur.wipe();
        }
        if (!n.cur.active && !n.prev.active) {
            dead[n_dead++] = &n;
        }
    });
    for (std::size_t i = 0; i < n_dead; ++i) {
        if (n_released < cap) {
            released[n_released++] = dead[i]->peer;
        }
        remove(*dead[i]);
    }
    return n_released;
}

MonoTime Neighbors::next_expiry() const {
    MonoTime next = MonoTime::never();
    const_cast<Table &>(table_).for_each([&](Handle, Neighbor &n) {
        if (n.cur.active) {
            next = earliest(next, n.cur.valid_until);
        }
        if (n.prev.active) {
            next = earliest(next, n.prev.valid_until);
        }
    });
    return next;
}

} // namespace lm::link
