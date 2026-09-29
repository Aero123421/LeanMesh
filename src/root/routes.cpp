#include "root/routes.hpp"

#include <algorithm>

#include "core/engine.hpp"

namespace lm::root {
namespace {

constexpr uint64_t k_lease_ms = gen::defaults::routing::lease_ms;
constexpr Duration k_push_gap = Duration::from_ms(40); // descendants are told one at a time

} // namespace

void Routes::stop() {
    inited_ = false;
    push_mask_ = 0;
    push_at_ = MonoTime::never();
}

void Routes::forget(ShortAddr addr) {
    if (inited_) {
        (void)topo_.remove(addr); // NotFound: it never registered
    }
    if (addr.value() >= 2 && addr.value() - 2U < 64U) {
        push_mask_ &= ~(1ULL << (addr.value() - 2U));
    }
}

// The tree is bound to the root's address and term (its MemberCredential); a changed pair starts a new one.
void Routes::sync(MonoTime /*now*/) {
    const member::MemberCredential &mc = engine_.identity().member();
    if (!inited_ || topo_.root_addr() != mc.address || topo_.term() != mc.root_term) {
        topo_.init(mc.address, mc.root_term);
        inited_ = true;
        push_mask_ = 0;
    }
}

bool Routes::path_to_addr(ShortAddr dest, delivery::PathSpec &out, MonoTime now) {
    sync(now);
    SourceRoute sr;
    if (topo_.route_between(topo_.root_addr(), dest, ms(now), sr) != Status::Ok || sr.len == 0) {
        return false;
    }
    out = delivery::PathSpec{};
    out.origin = topo_.root_addr();
    out.dest = dest;
    out.len = sr.len;
    std::copy(sr.path.begin(), sr.path.begin() + sr.len, out.path.begin());
    out.term = topo_.term();
    out.revision = sr.revision;
    return true;
}

// Who is this member? Its ACTIVE ledger entry, and an end session (if any) of exactly that entry's address and
// generations (SEC-D2: the ledger admitted it). A device the ledger does not list gets nothing (S8-D7 is gone).
// Never by an address alone.
bool Routes::identify(const DeviceId &dev, ShortAddr &addr, uint64_t &gen) {
    const delivery::EndSession *s = engine_.delivery().sessions().find_peer(dev);
    const Entry *e = engine_.ledger().find(dev);
    if (e == nullptr || e->state != EntryState::Active ||
        (s != nullptr && (e->address != s->peer_addr || e->assignment != s->peer_assignment.value() ||
                          e->membership != s->peer_membership.value()))) {
        return false;
    }
    addr = e->address;
    gen = e->membership;
    return true;
}

bool Routes::path_to(const DeviceId &dest, delivery::PathSpec &out, MonoTime now) {
    ShortAddr addr;
    uint64_t gen = 0;
    return identify(dest, addr, gen) && path_to_addr(addr, out, now);
}

void Routes::send_lease(const DeviceId &peer, const delivery::PathSpec &route, route::LeaseRec &l, MonoTime now,
                        uint32_t lease_ms) {
    l.term = topo_.term().value();
    l.lease_ms = lease_ms != 0 ? lease_ms : static_cast<uint32_t>(k_lease_ms);
    l.expected_revision = static_cast<uint32_t>(engine_.ledger().expected_revision());
    std::array<uint8_t, 64> body{};
    std::size_t len = 0;
    if (route::encode(l, MutByteView{body}, len) == Status::Ok) {
        (void)engine_.delivery().send_control(peer, route, ByteView{body.data(), len}, now); // lost: the node asks again
    }
}

void Routes::on_control(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now) {
    sync(now);
    // Who is asking: the end session says (verified MemberCredential) and the ledger must not object.
    // Anyone else gets no answer at all.
    ShortAddr addr;
    uint64_t gen = 0;
    if (!identify(peer, addr, gen)) {
        return;
    }
    switch (static_cast<route::Op>(body[0])) {
    case route::Op::Register:
        on_register(peer, addr, gen, reply, body, now);
        break;
    case route::Op::Ready:
        on_ready(peer, addr, reply, body, now);
        break;
    case route::Op::Query:
        on_query(peer, reply, body, now);
        break;
    case route::Op::Power: // [S16] the member's schedule hint
        engine_.power().on_report(peer, addr, body, now);
        break;
    default:
        break;
    }
}

// REGISTER: validate against the current tree only (rank and advertisements are no proof, docs/04 §3).
void Routes::on_register(const DeviceId &peer, ShortAddr addr, uint64_t gen, const delivery::PathSpec &reply,
                         ByteView body, MonoTime now) {
    route::Register r;
    if (route::decode(body, r) != Status::Ok) {
        return;
    }
    ++stats_.registers;
    route::LeaseRec l;
    RouteGrant g;
    Status st = topo_.admit(addr, gen);
    RouteGrant parent_path;
    const bool parent_is_root = r.parent == topo_.root_addr().value();
    if (st == Status::Ok) {
        if (parent_is_root) {
            parent_path.path[0] = topo_.root_addr().value();
            parent_path.len = 1;
        } else {
            st = topo_.path_from_root(ShortAddr{r.parent}, ms(now), parent_path);
            PathRevision pr;
            if (st == Status::Ok && topo_.path_revision(ShortAddr{r.parent}, pr) == Status::Ok &&
                pr.value() != r.parent_revision) {
                st = Status::NoRoute; // the node built its request from an advertisement that has moved on
                l.revision = pr.value(); // ... and gets the current revision to try again at once
            }
        }
    }
    if (st == Status::Ok) {
        std::array<uint16_t, k_max_depth + 1> cand{};
        std::copy(parent_path.path.begin(), parent_path.path.begin() + parent_path.len, cand.begin());
        cand[parent_path.len] = addr.value();
        RouteRequest rq;
        rq.node = addr;
        rq.term = RootTerm{r.term};
        rq.parent = ShortAddr{r.parent};
        rq.candidate_path = cand.data();
        rq.candidate_len = parent_path.len + 1U;
        rq.request_sequence = r.sequence;
        st = topo_.register_route(rq, ms(now), g);
    }
    l.status = st;
    if (st == Status::Ok) {
        ++stats_.grants;
        l.revision = g.revision.value();
        l.n = g.len;
        std::copy(g.path.begin(), g.path.begin() + g.len, l.path.begin());
    } else {
        ++stats_.refused;
    }
    (void)peer;
    send_lease(peer, reply, l, now);
}

// READY: the node applied the grant (first time) or renews its lease (later). The answer carries the current path.
void Routes::on_ready(const DeviceId &peer, ShortAddr addr, const delivery::PathSpec &reply, ByteView body,
                      MonoTime now) {
    route::Ready r;
    if (route::decode(body, r) != Status::Ok) {
        return;
    }
    ++stats_.readies;
    PathRevision before;
    (void)topo_.path_revision(addr, before);
    route::LeaseRec l;
    RouteGrant g;
    Status st = topo_.confirm_ready(addr, RootTerm{r.term}, PathRevision{r.revision}, ms(now));
    const uint32_t lease = engine_.power().lease_ms_for(addr, now); // [S16] longer for a sleepy member, never unbounded
    if (st == Status::Ok) {
        st = topo_.renew(addr, ms(now), g, lease);
    }
    l.status = st;
    if (st == Status::Ok) {
        l.revision = g.revision.value();
        l.n = g.len;
        std::copy(g.path.begin(), g.path.begin() + g.len, l.path.begin());
        if (g.revision != before) { // the tree changed under this node: its descendants' paths did too
            topo_.for_each_descendant(addr, [&](ShortAddr d) {
                if (d.value() >= 2 && d.value() - 2U < 64U) {
                    push_mask_ |= 1ULL << (d.value() - 2U);
                }
            });
            if (push_mask_ != 0 && push_at_.is_never()) {
                push_at_ = now + k_push_gap;
            }
        }
    }
    send_lease(peer, reply, l, now, lease);
    engine_.ledger().renew_due(peer, r.term, r.credential_lease_ms, now); // [S18] after the answer: never delays it
}

void Routes::on_query(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now) {
    route::Query q;
    if (route::decode(body, q) != Status::Ok) {
        return;
    }
    ++stats_.queries;
    route::Answer a;
    a.qid = q.qid;
    a.status = Status::NotFound;
    RouteGrant g;
    if (q.dest == engine_.identity().self()) {
        a.status = Status::Ok;
        a.dest = topo_.root_addr().value();
        a.n = 1;
        a.path[0] = a.dest;
    } else {
        ShortAddr da;
        uint64_t dgen = 0;
        if (identify(q.dest, da, dgen)) {
            a.status = topo_.path_from_root(da, ms(now), g);
            if (a.status == Status::Ok) {
                a.dest = da.value();
                a.revision = g.revision.value();
                a.n = g.len;
                std::copy(g.path.begin(), g.path.begin() + g.len, a.path.begin());
            }
        }
    }
    std::array<uint8_t, 96> out{};
    std::size_t len = 0;
    if (route::encode(a, MutByteView{out}, len) == Status::Ok) {
        (void)engine_.delivery().send_control(peer, reply, ByteView{out.data(), len}, now);
    }
}

// Tells one moved descendant its new path (root -> node along the tree, an unsolicited LEASE).
void Routes::push_next(MonoTime now) {
    push_at_ = MonoTime::never();
    while (push_mask_ != 0) {
        const auto slot = static_cast<std::size_t>(__builtin_ctzll(push_mask_));
        push_mask_ &= push_mask_ - 1U;
        const delivery::EndSession *s = engine_.delivery().end_session_at(ShortAddr{static_cast<uint16_t>(2 + slot)});
        RouteGrant g;
        delivery::PathSpec route;
        if (s == nullptr || topo_.path_from_root(s->peer_addr, ms(now), g) != Status::Ok ||
            !path_to_addr(s->peer_addr, route, now) || !engine_.delivery().has_session(s->peer, now)) {
            continue; // not in the tree any more, or no end session: it re-registers by its own renewal
        }
        route::LeaseRec l;
        l.push = true;
        l.revision = g.revision.value();
        l.n = g.len;
        std::copy(g.path.begin(), g.path.begin() + g.len, l.path.begin());
        send_lease(s->peer, route, l, now);
        ++stats_.pushes;
        break;
    }
    if (push_mask_ != 0) {
        push_at_ = now + k_push_gap;
    }
}

void Routes::extend_lease(ShortAddr addr, uint32_t lease_ms, MonoTime now) {
    RouteGrant g;
    if (inited_) {
        (void)topo_.renew(addr, ms(now), g, lease_ms); // not active (yet): nothing to extend, it attaches first
    }
}

void Routes::on_timer(MonoTime now) {
    if (!inited_) {
        return;
    }
    topo_.expire(ms(now));
    if (now >= push_at_) {
        push_next(now);
    }
}

MonoTime Routes::deadline() const {
    MonoTime d = push_at_;
    const uint64_t exp = topo_.next_expiry_ms();
    if (exp != UINT64_MAX) {
        d = earliest(d, MonoTime{exp * 1000ULL + 1000ULL});
    }
    return d;
}

} // namespace lm::root
