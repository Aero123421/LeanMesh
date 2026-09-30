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
        }
    });
    if (found == nullptr) {
        for (Grace &g : grace_) {
            if (g.keys.active && g.mac == mac && g.keys.rx_sid == sid) {
                found = find_mac(mac); // a session that outlived its neighbour is not served
                which = &g.keys;
            }
        }
    }
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
        used = used || (n.cur.active && n.cur.rx_sid == sid);
    });
    for (const Grace &g : grace_) {
        used = used || (g.keys.active && g.keys.rx_sid == sid);
    }
    return used;
}

void Neighbors::retire(const MacAddr &mac, SessionKeys &&old, MonoTime until) {
    Grace *slot = &grace_[0];
    for (Grace &g : grace_) {
        if (!g.keys.active || g.mac == mac) {
            slot = &g; // a free slot, or the same neighbour's older grace (never two per neighbour)
            if (g.mac == mac || !g.keys.active) {
                break;
            }
        } else if (slot->keys.active && g.keys.valid_until < slot->keys.valid_until) {
            slot = &g; // both busy with others: the one that ends first goes
        }
    }
    slot->keys.wipe();
    slot->mac = mac;
    slot->keys = std::move(old);
    slot->keys.valid_until = earliest(slot->keys.valid_until, until);
}

bool Neighbors::has_grace(const MacAddr &mac) const {
    for (const Grace &g : grace_) {
        if (g.keys.active && g.mac == mac) {
            return true;
        }
    }
    return false;
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
    for (Grace &g : grace_) {
        if (g.keys.active && g.mac == n.mac) {
            g.keys.wipe();
        }
    }
    (void)table_.release(target);
}

std::size_t Neighbors::sweep(MonoTime now, PeerHandle *released, std::size_t cap) {
    std::size_t n_released = 0;
    Neighbor *dead[k_max_neighbors];
    std::size_t n_dead = 0;
    table_.for_each([&](Handle, Neighbor &n) {
        if (n.cur.active && !live(n.cur, now)) {
            n.cur.wipe();
        }
        if (!n.cur.active) {
            dead[n_dead++] = &n;
        }
    });
    for (Grace &g : grace_) {
        if (g.keys.active && !live(g.keys, now)) {
            g.keys.wipe();
        }
    }
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
    });
    for (const Grace &g : grace_) {
        if (g.keys.active) {
            next = earliest(next, g.keys.valid_until);
        }
    }
    return next;
}

} // namespace lm::link
