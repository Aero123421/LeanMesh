#include "core/radio/peer_registry.hpp"

namespace lm {

bool PeerRegistry::find(const MacAddr &mac, PeerHandle &out) const {
    // Linear scan over <= 19 entries (docs/15 §2: small sets stay arrays).
    auto scan = [&](auto &pool, PeerClass cls) {
        for (std::size_t i = 0; i < pool.capacity(); ++i) {
            const Handle h = pool.handle_at(i);
            const Entry *e = pool.get(h);
            if (e != nullptr && e->mac == mac) {
                out = PeerHandle{cls, h};
                return true;
            }
        }
        return false;
    };
    return scan(regular_, PeerClass::Regular) || scan(transient_, PeerClass::Transient);
}

bool PeerRegistry::has(const MacAddr &mac) const {
    PeerHandle unused;
    return find(mac, unused);
}

bool PeerRegistry::valid(PeerHandle h) const { return mac_of(h) != nullptr; }

const MacAddr *PeerRegistry::mac_of(PeerHandle h) const {
    const Entry *e = h.cls == PeerClass::Regular ? regular_.get(h.slot) : transient_.get(h.slot);
    return e == nullptr ? nullptr : &e->mac;
}

Status PeerRegistry::acquire(port::Radio &radio, const MacAddr &mac, PeerClass cls,
                             PeerHandle &out) {
    if (mac.is_broadcast()) {
        return Status::InvalidArgument; // the broadcast peer is owned by the Engine, not leased
    }
    PeerHandle existing;
    if (find(mac, existing)) {
        if (existing.cls != cls) {
            return Status::Conflict;
        }
        out = existing;
        return Status::Ok;
    }
    const Handle h = cls == PeerClass::Regular ? regular_.acquire() : transient_.acquire();
    if (h.is_none()) {
        return Status::NoCapacity;
    }
    const Status s = radio.add_peer(mac);
    if (s != Status::Ok) {
        (void)(cls == PeerClass::Regular ? regular_.release(h) : transient_.release(h));
        return s;
    }
    (cls == PeerClass::Regular ? regular_.get(h) : transient_.get(h))->mac = mac;
    out = PeerHandle{cls, h};
    return Status::Ok;
}

Status PeerRegistry::release(port::Radio &radio, PeerHandle h) {
    const MacAddr *mac = mac_of(h);
    if (mac == nullptr) {
        return Status::NotFound;
    }
    const Status s = radio.remove_peer(*mac); // *mac dies with the slot: use before release
    if (s != Status::Ok && s != Status::NotFound) {
        return s;
    }
    (void)(h.cls == PeerClass::Regular ? regular_.release(h.slot) : transient_.release(h.slot));
    return Status::Ok;
}

Status PeerRegistry::promote(PeerHandle transient, PeerHandle &regular_out) {
    if (transient.cls != PeerClass::Transient || !valid(transient)) {
        return Status::NotFound;
    }
    const Handle h = regular_.acquire();
    if (h.is_none()) {
        return Status::NoCapacity;
    }
    regular_.get(h)->mac = *mac_of(transient);
    (void)transient_.release(transient.slot);
    regular_out = PeerHandle{PeerClass::Regular, h};
    return Status::Ok;
}

Status PeerRegistry::demote(PeerHandle regular, PeerHandle &transient_out) {
    if (regular.cls != PeerClass::Regular || !valid(regular)) {
        return Status::NotFound;
    }
    const Handle h = transient_.acquire();
    if (h.is_none()) {
        return Status::NoCapacity;
    }
    transient_.get(h)->mac = *mac_of(regular);
    (void)regular_.release(regular.slot);
    transient_out = PeerHandle{PeerClass::Transient, h};
    return Status::Ok;
}

Status PeerRegistry::reapply(port::Radio &radio) const {
    Status first = Status::Ok;
    auto each = [&](const auto &pool) {
        for (std::size_t i = 0; i < pool.capacity(); ++i) {
            const Entry *e = pool.get(pool.handle_at(i));
            if (e != nullptr) {
                const Status s = radio.add_peer(e->mac);
                first = first == Status::Ok ? s : first;
            }
        }
    };
    each(regular_);
    each(transient_);
    return first;
}

} // namespace lm
