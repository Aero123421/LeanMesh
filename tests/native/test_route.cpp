// Route model (docs/04): per-hop forwarding checks (R04), integer score/ETX vectors, bounded path
// cache, and the root's approved tree, including the seeded model test R03. The model drives the
// production `root::Topology` with stale advertisements, reordered/duplicated/lost register, ACK
// and READY messages, lease expiry, address reuse and root_term changes, and checks the tree
// invariants after every step through the public API only. On a violation it prints the seed, the
// operation trace and the smallest node count that still fails (rerun: LM_ROUTE_SEED=<seed>).
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "core/route/forward.hpp"
#include "core/route/path_cache.hpp"
#include "core/route/score.hpp"
#include "lmtest.hpp"
#include "root/topology.hpp"

using namespace lm;
using namespace lm::route;
using lm::root::RouteGrant;
using lm::root::RouteRequest;
using lm::root::SourceRoute;
using lm::root::Topology;

namespace {

constexpr uint16_t k_root_addr = 1;

wire::RouteHeader make_header(uint16_t origin, const std::vector<uint16_t> &path, uint32_t term) {
    wire::RouteHeader h;
    h.origin = origin;
    h.final = path.back();
    h.path_len = static_cast<uint8_t>(path.size());
    h.budget = h.path_len;
    h.root_term = term;
    std::copy(path.begin(), path.end(), h.path.begin());
    return h;
}

// Walks a source route hop by hop with the production decision function. Returns the number of
// nodes that forwarded; -1 when a hop dropped, and checks that no node handles the packet twice.
int walk(wire::RouteHeader h, uint32_t term) {
    std::vector<uint16_t> seen;
    uint16_t prev = h.origin;
    int forwarded = 0;
    for (std::size_t guard = 0; guard <= wire::k_max_path + 1; ++guard) {
        const uint16_t self = h.path[h.next_index];
        if (std::find(seen.begin(), seen.end(), self) != seen.end()) {
            return -2;
        }
        seen.push_back(self);
        const Decision d = decide_forward(h, ShortAddr{self}, ShortAddr{prev}, RootTerm{term});
        if (d.action == Action::Drop) {
            return -1;
        }
        if (d.action == Action::Deliver) {
            return self == h.final ? forwarded : -3;
        }
        ++forwarded;
        prev = self;
    }
    return -4;
}

std::vector<uint16_t> seq_path(uint16_t first, std::size_t n) {
    std::vector<uint16_t> p;
    for (std::size_t i = 0; i < n; ++i) {
        p.push_back(static_cast<uint16_t>(first + i));
    }
    return p;
}

} // namespace

LM_TEST("R04 forwarding: duplicate address, wrong peer, stale term, budget are dropped") {
    const auto ok = make_header(10, {11, 12, 13}, 7);
    LM_CHECK_EQ(walk(ok, 7), 2); // 11 and 12 forward, 13 delivers

    auto dup = make_header(10, {11, 12, 11, 13}, 7); // authenticated frame, repeated address
    LM_CHECK_EQ(static_cast<int>(decide_forward(dup, ShortAddr{11}, ShortAddr{10}, RootTerm{7}).reason),
                static_cast<int>(DropReason::NotSimple));
    uint8_t buf[300];
    std::size_t len = 0;
    // The codec refuses the same frame before it reaches the forwarder.
    wire::RouteHeader parsed;
    ByteView end;
    const Status enc = wire::encode_route(dup, MutByteView{buf, sizeof buf}, len);
    LM_CHECK(enc != Status::Ok || wire::decode_route(ByteView{buf, len}, parsed, end) != Status::Ok);

    auto h = ok;
    LM_CHECK(decide_forward(h, ShortAddr{12}, ShortAddr{10}, RootTerm{7}).reason == DropReason::NotSelf);
    h = ok;
    LM_CHECK(decide_forward(h, ShortAddr{11}, ShortAddr{99}, RootTerm{7}).reason ==
             DropReason::WrongPrevious);
    h = ok;
    LM_CHECK(decide_forward(h, ShortAddr{11}, ShortAddr{10}, RootTerm{8}).reason == DropReason::StaleTerm);
    h = ok;
    h.budget = 0;
    LM_CHECK(decide_forward(h, ShortAddr{11}, ShortAddr{10}, RootTerm{7}).reason == DropReason::NoBudget);
    h = ok;
    h.budget = 9;
    LM_CHECK(decide_forward(h, ShortAddr{11}, ShortAddr{10}, RootTerm{7}).reason == DropReason::NoBudget);
    h = ok;
    h.final = 99;
    LM_CHECK(decide_forward(h, ShortAddr{11}, ShortAddr{10}, RootTerm{7}).reason ==
             DropReason::FinalMismatch);
    h = ok;
    h.next_index = 3;
    LM_CHECK(decide_forward(h, ShortAddr{13}, ShortAddr{12}, RootTerm{7}).reason == DropReason::BadIndex);
    h = ok;
    LM_CHECK(decide_forward(h, ShortAddr{10}, ShortAddr{10}, RootTerm{7}).reason ==
             DropReason::OriginIsSelf);
    // Zero and broadcast addresses inside the path.
    h = make_header(10, {11, 0, 13}, 7);
    LM_CHECK(decide_forward(h, ShortAddr{11}, ShortAddr{10}, RootTerm{7}).reason == DropReason::NotSimple);
    // A forward changes exactly next_index and budget.
    h = ok;
    const Decision d = decide_forward(h, ShortAddr{11}, ShortAddr{10}, RootTerm{7});
    LM_CHECK(d.action == Action::Forward && d.next_hop.value() == 12);
    LM_CHECK_EQ(h.next_index, 1);
    LM_CHECK_EQ(h.budget, 2);
    // 20-hop and 40-hop routes each traverse every node once.
    LM_CHECK_EQ(walk(make_header(5, seq_path(100, 20), 1), 1), 19);
    LM_CHECK_EQ(walk(make_header(5, seq_path(100, 40), 1), 1), 39);
}

LM_TEST("candidate path: self, duplicates, depth 21, other term and expiry are refused") {
    const auto p = seq_path(1, 19);
    LM_CHECK_OK(check_candidate_path(ShortAddr{500}, p.data(), 19, RootTerm{3}, RootTerm{3}, false));
    const auto p20 = seq_path(1, 20); // this node would sit at depth 21
    LM_CHECK(check_candidate_path(ShortAddr{500}, p20.data(), 20, RootTerm{3}, RootTerm{3}, false) ==
             Status::Ok);
    const auto p21 = seq_path(1, 21);
    LM_CHECK(check_candidate_path(ShortAddr{500}, p21.data(), 21, RootTerm{3}, RootTerm{3}, false) ==
             Status::NoRoute);
    LM_CHECK(check_candidate_path(ShortAddr{5}, p.data(), 19, RootTerm{3}, RootTerm{3}, false) ==
             Status::InvalidArgument);
    const std::vector<uint16_t> dup{1, 2, 1};
    LM_CHECK(check_candidate_path(ShortAddr{500}, dup.data(), 3, RootTerm{3}, RootTerm{3}, false) ==
             Status::InvalidArgument);
    LM_CHECK(check_candidate_path(ShortAddr{500}, p.data(), 19, RootTerm{2}, RootTerm{3}, false) ==
             Status::NetworkMismatch);
    LM_CHECK(check_candidate_path(ShortAddr{500}, p.data(), 19, RootTerm{3}, RootTerm{3}, true) ==
             Status::Expired);
}

LM_TEST("score: EWMA, ETX_Q8, queue, penalty and score vectors of docs/04 s6") {
    LinkQuality q;
    LM_CHECK_EQ(q.etx_q8(), 256);
    q.record_attempt(false);
    LM_CHECK_EQ(q.success_q16, 57344);
    LM_CHECK_EQ(q.etx_q8(), 292);
    q.record_attempt(false);
    LM_CHECK_EQ(q.success_q16, 50176);
    LM_CHECK_EQ(q.etx_q8(), 334);
    q.record_attempt(true);
    LM_CHECK_EQ(q.success_q16, 52096);
    LM_CHECK_EQ(q.etx_q8(), 322);
    for (int i = 0; i < 300; ++i) {
        q.record_attempt(false);
    }
    LM_CHECK_EQ(q.etx_q8(), 4096); // clamped
    LinkQuality up;
    for (int i = 0; i < 300; ++i) {
        up.record_attempt(true);
    }
    LM_CHECK_EQ(up.etx_q8(), 256);

    LinkQuality w;
    w.record_queue_ms(500);
    LM_CHECK_EQ(w.queue_ms, 62);
    w.record_queue_ms(500);
    LM_CHECK_EQ(w.queue_ms, 116);
    w.record_queue_ms(100000); // sample clipped to 500
    LM_CHECK_EQ(w.queue_ms, 164);

    LinkQuality s;
    s.record_attempt(false); // ETX 292
    s.queue_ms = 62;
    LM_CHECK_EQ(parent_score(3, s, 128), 768U + 292U - 256U + 62U + 128U);

    Instability inst;
    const MonoTime t0{1'000'000};
    for (int i = 0; i < 6; ++i) {
        inst.note_change(t0);
    }
    LM_CHECK_EQ(inst.penalty(t0), 512);
    LM_CHECK_EQ(inst.penalty(t0 + Duration::from_s(29)), 512);
    LM_CHECK_EQ(inst.penalty(t0 + Duration::from_s(30)), 384);
    LM_CHECK_EQ(inst.penalty(t0 + Duration::from_s(60)), 256);
    LM_CHECK_EQ(inst.penalty(t0 + Duration::from_s(120)), 0);
}

LM_TEST("score: unknown candidates never win, ties by DeviceId, switch rule") {
    std::array<Candidate, 3> c{};
    c[0].id.bytes[0] = 9;
    c[1].id.bytes[0] = 5;
    c[2].id.bytes[0] = 7;
    for (auto &x : c) {
        x.depth = 2;
    }
    c[0].quality.record_attempt(true); // known, same score as c[1]
    c[1].quality.record_attempt(true);
    // c[2] stays unknown although its default numbers would score equal or better.
    LM_CHECK_EQ(pick_best(c.data(), 3), 1); // lower DeviceId wins the tie
    c[1].penalty = 128;
    LM_CHECK_EQ(pick_best(c.data(), 3), 0);
    std::array<Candidate, 2> none{};
    LM_CHECK_EQ(pick_best(none.data(), 2), -1);

    LM_CHECK(should_switch(1000, 800, Duration::from_s(30), false));
    LM_CHECK(!should_switch(1000, 801, Duration::from_s(30), false)); // 20 % needed
    LM_CHECK(!should_switch(1000, 100, Duration::from_ms(29999), false));
    LM_CHECK(should_switch(1000, 999, Duration::from_ms(1), true)); // dead link: no hold
}

LM_TEST("path cache: bounded, LRU replacement, revision/term/expiry/membership invalidation") {
    PathCache<4> cache;
    const ShortAddr self{10};
    auto route = [](uint16_t dest, uint32_t rev, uint32_t term) {
        CachedRoute r;
        r.destination = ShortAddr{dest};
        r.root_term = RootTerm{term};
        r.revision = PathRevision{rev};
        r.len = 2;
        r.path[0] = static_cast<uint16_t>(dest + 100);
        r.path[1] = dest;
        return r;
    };
    const MonoTime now{0};
    const MonoTime later = now + Duration::from_s(10);
    for (uint16_t d = 20; d < 24; ++d) {
        LM_CHECK_OK(cache.put(self, route(d, 1, 1), later));
    }
    LM_CHECK_EQ(cache.size(), 4);
    CachedRoute out;
    LM_CHECK_OK(cache.lookup(ShortAddr{20}, RootTerm{1}, now, out)); // 20 becomes most recent
    LM_CHECK_OK(cache.put(self, route(30, 1, 1), later));            // evicts 21 (LRU)
    LM_CHECK_EQ(cache.size(), 4);
    LM_CHECK(cache.lookup(ShortAddr{21}, RootTerm{1}, now, out) == Status::NotFound);
    LM_CHECK_OK(cache.lookup(ShortAddr{20}, RootTerm{1}, now, out));
    LM_CHECK(cache.put(self, route(20, 0, 1), later) == Status::Conflict); // older revision
    LM_CHECK_OK(cache.put(self, route(20, 2, 1), later));
    LM_CHECK(cache.lookup(ShortAddr{20}, RootTerm{2}, now, out) == Status::NotFound); // other term
    LM_CHECK(cache.lookup(ShortAddr{22}, RootTerm{1}, later, out) == Status::NotFound); // expired
    LM_CHECK_OK(cache.put(self, route(40, 1, 1), later));
    cache.invalidate_addr(ShortAddr{140}); // hop of 40's route
    LM_CHECK(cache.lookup(ShortAddr{40}, RootTerm{1}, now, out) == Status::NotFound);
    auto bad = route(50, 1, 1);
    bad.path[0] = 50; // duplicate
    LM_CHECK(cache.put(self, bad, later) == Status::InvalidArgument);
    bad = route(10, 1, 1); // destination is self
    LM_CHECK(cache.put(self, bad, later) == Status::InvalidArgument);
}

namespace {

DeviceId dev(unsigned i) {
    DeviceId d;
    d.bytes[0] = static_cast<uint8_t>(i >> 8);
    d.bytes[1] = static_cast<uint8_t>(i);
    d.bytes[31] = 1;
    return d;
}
uint16_t addr_of(unsigned i) { return static_cast<uint16_t>(i + 2); } // 1 is the root

// One register request built from the parent's current approved path; then READY.
Status attach(Topology &t, unsigned node, uint16_t parent, uint32_t seq, uint64_t now,
              bool ready, RouteGrant *grant_out = nullptr) {
    RouteGrant path;
    if (parent == k_root_addr) {
        path.path[0] = k_root_addr;
        path.len = 1;
    } else {
        const Status st = t.path_from_root(ShortAddr{parent}, now, path);
        if (st != Status::Ok) {
            return st;
        }
    }
    std::vector<uint16_t> cand(path.path.begin(), path.path.begin() + path.len);
    cand.push_back(addr_of(node));
    RouteRequest rq;
    rq.device = dev(node);
    rq.assignment = AssignmentGen{1};
    rq.membership = MembershipGen{1};
    rq.term = t.term();
    rq.parent = ShortAddr{parent};
    rq.candidate_path = cand.data();
    rq.candidate_len = cand.size();
    rq.request_sequence = seq;
    RouteGrant g;
    LM_TRY(t.register_route(rq, now, g));
    if (grant_out != nullptr) {
        *grant_out = g;
    }
    return ready ? t.confirm_ready(dev(node), t.term(), g.revision, now) : Status::Ok;
}

void admit_n(Topology &t, unsigned n) {
    for (unsigned i = 0; i < n; ++i) {
        LM_CHECK_OK(t.admit(dev(i), ShortAddr{addr_of(i)}, AssignmentGen{1}, MembershipGen{1}));
    }
}

} // namespace

LM_TEST("topology: depth 20 accepted, 21 refused, 40-hop LCA path forwards end to end") {
    Topology t{ShortAddr{k_root_addr}, RootTerm{1}};
    admit_n(t, 41);
    // Two 20-deep branches: nodes 0..19 and 20..39; node 40 tries to be the 21st on branch one.
    uint32_t seq = 1;
    for (unsigned i = 0; i < 20; ++i) {
        LM_CHECK_OK(attach(t, i, i == 0 ? k_root_addr : addr_of(i - 1), seq++, 1000, true));
        LM_CHECK_OK(attach(t, 20 + i, i == 0 ? k_root_addr : addr_of(20 + i - 1), seq++, 1000, true));
    }
    LM_CHECK(attach(t, 40, addr_of(19), 1, 1000, true) == Status::InvalidArgument); // > 21 addresses
    SourceRoute r;
    LM_CHECK_OK(t.route_between(ShortAddr{addr_of(19)}, ShortAddr{addr_of(39)}, 1000, r));
    LM_CHECK_EQ(r.len, 40);
    std::vector<uint16_t> path(r.path.begin(), r.path.begin() + r.len);
    LM_CHECK_EQ(walk(make_header(addr_of(19), path, 1), 1), 39);
    // Ancestor/descendant and root endpoints.
    LM_CHECK_OK(t.route_between(ShortAddr{addr_of(3)}, ShortAddr{addr_of(6)}, 1000, r));
    LM_CHECK_EQ(r.len, 3);
    LM_CHECK_EQ(r.path[0], addr_of(4));
    LM_CHECK_OK(t.route_between(ShortAddr{addr_of(6)}, ShortAddr{addr_of(3)}, 1000, r));
    LM_CHECK_EQ(r.len, 3);
    LM_CHECK_EQ(r.path[2], addr_of(3));
    LM_CHECK_OK(t.route_between(ShortAddr{addr_of(0)}, ShortAddr{k_root_addr}, 1000, r));
    LM_CHECK_EQ(r.len, 1);
    LM_CHECK_OK(t.route_between(ShortAddr{k_root_addr}, ShortAddr{addr_of(2)}, 1000, r));
    LM_CHECK_EQ(r.len, 3);
    LM_CHECK(t.route_between(ShortAddr{addr_of(2)}, ShortAddr{addr_of(2)}, 1000, r) ==
             Status::InvalidArgument);
    LM_CHECK(t.route_between(ShortAddr{addr_of(2)}, ShortAddr{addr_of(40)}, 1000, r) ==
             Status::NoRoute); // never approved
    // A move that would push a descendant beyond depth 20, and a move under the node's own
    // descendant (cycle), are refused and leave the tree as it was.
    LM_CHECK(attach(t, 0, addr_of(29), 9, 1000, true) == Status::Conflict);
    LM_CHECK(attach(t, 0, addr_of(5), 10, 1000, true) == Status::InvalidArgument); // path holds self
    LM_CHECK_OK(t.route_between(ShortAddr{addr_of(19)}, ShortAddr{addr_of(39)}, 1000, r));
    LM_CHECK_EQ(r.len, 40);
}

LM_TEST("topology: pending until READY, lost-ACK replay, stale advertisement, sequence rules") {
    Topology t{ShortAddr{k_root_addr}, RootTerm{5}};
    admit_n(t, 4);
    RouteGrant g1;
    RouteGrant g2;
    LM_CHECK_OK(attach(t, 0, k_root_addr, 1, 0, false, &g1));
    ShortAddr parent;
    LM_CHECK(t.parent_of(ShortAddr{addr_of(0)}, parent) == Status::NotFound); // not applied yet
    LM_CHECK_EQ(g1.len, 2);
    LM_CHECK_EQ(g1.path[0], k_root_addr);
    LM_CHECK_EQ(g1.path[1], addr_of(0));
    // ACK lost: the same request returns the same grant, revision unchanged.
    LM_CHECK_OK(attach(t, 0, k_root_addr, 1, 10, false, &g2));
    LM_CHECK_EQ(g2.revision.value(), g1.revision.value());
    LM_CHECK(attach(t, 0, k_root_addr, 0, 10, false) == Status::Conflict); // older sequence
    LM_CHECK_OK(t.confirm_ready(dev(0), RootTerm{5}, g1.revision, 20));
    LM_CHECK_OK(t.confirm_ready(dev(0), RootTerm{5}, g1.revision, 30)); // duplicate READY
    LM_CHECK_OK(t.parent_of(ShortAddr{addr_of(0)}, parent));
    LM_CHECK_EQ(parent.value(), k_root_addr);
    LM_CHECK_OK(attach(t, 0, k_root_addr, 1, 40, false, &g2)); // replay after READY
    LM_CHECK_EQ(g2.revision.value(), g1.revision.value());
    LM_CHECK(t.confirm_ready(dev(0), RootTerm{5}, PathRevision{999}, 30) == Status::Conflict);
    LM_CHECK(t.confirm_ready(dev(0), RootTerm{4}, g1.revision, 30) == Status::NetworkMismatch);

    // Stale advertisement: node 1 registers under node 0 with the path node 0 had before it moved.
    LM_CHECK_OK(attach(t, 2, k_root_addr, 1, 50, true));
    LM_CHECK_OK(attach(t, 0, addr_of(2), 2, 50, true)); // 0 moves below 2
    const std::vector<uint16_t> stale{k_root_addr, addr_of(0), addr_of(1)};
    RouteRequest rq;
    rq.device = dev(1);
    rq.assignment = AssignmentGen{1};
    rq.membership = MembershipGen{1};
    rq.term = RootTerm{5};
    rq.parent = ShortAddr{addr_of(0)};
    rq.candidate_path = stale.data();
    rq.candidate_len = stale.size();
    rq.request_sequence = 1;
    RouteGrant g;
    LM_CHECK(t.register_route(rq, 60, g) == Status::NoRoute);
    rq.term = RootTerm{4};
    LM_CHECK(t.register_route(rq, 60, g) == Status::NetworkMismatch);
    rq.term = RootTerm{5};
    rq.membership = MembershipGen{2};
    LM_CHECK(t.register_route(rq, 60, g) == Status::TargetGenerationChanged);
    // Renewal keeps the lease, expiry removes only the link.
    LM_CHECK_OK(t.renew(dev(2), 100000, g));
    LM_CHECK_EQ(g.lease_expires_ms, 100000U + 180000U);
    t.expire(100000U + 180000U);
    RouteGrant none;
    LM_CHECK(t.path_from_root(ShortAddr{addr_of(2)}, 300000, none) == Status::NoRoute);
    LM_CHECK(t.path_from_root(ShortAddr{addr_of(0)}, 300000, none) == Status::NoRoute); // via 2
}

LM_TEST("R03 simultaneous parent choice on old paths never closes a cycle") {
    Topology t{ShortAddr{k_root_addr}, RootTerm{1}};
    admit_n(t, 2); // A = node 0, B = node 1, both under the root, then each picks the other
    RouteGrant ga;
    RouteGrant gb;
    LM_CHECK_OK(attach(t, 0, k_root_addr, 1, 0, true));
    LM_CHECK_OK(attach(t, 1, addr_of(0), 1, 0, true)); // B below A
    // A now wants B as parent using B's path from before it moved below A (B was at [root, B]).
    const std::vector<uint16_t> old_b{k_root_addr, addr_of(1), addr_of(0)};
    RouteRequest rq;
    rq.device = dev(0);
    rq.assignment = AssignmentGen{1};
    rq.membership = MembershipGen{1};
    rq.term = RootTerm{1};
    rq.parent = ShortAddr{addr_of(1)};
    rq.candidate_path = old_b.data();
    rq.candidate_len = old_b.size();
    rq.request_sequence = 2;
    LM_CHECK(t.register_route(rq, 0, ga) != Status::Ok);
    // Both move at once: B re-registers under the root while A registers under B, ACKs reversed.
    LM_CHECK_OK(attach(t, 1, k_root_addr, 2, 0, false, &gb)); // pending: B under root
    LM_CHECK(t.path_from_root(ShortAddr{addr_of(1)}, 0, ga) == Status::Ok); // still [root,A,B]
    LM_CHECK_EQ(ga.len, 3);
    LM_CHECK(attach(t, 0, addr_of(1), 3, 0, false) != Status::Ok); // cycle: 1 is below 0
    LM_CHECK_OK(t.confirm_ready(dev(1), RootTerm{1}, gb.revision, 0));
    LM_CHECK_OK(attach(t, 0, addr_of(1), 3, 0, true)); // fine now: [root,B] is B's real path
    ShortAddr p;
    LM_CHECK_OK(t.parent_of(ShortAddr{addr_of(0)}, p));
    LM_CHECK_EQ(p.value(), addr_of(1));
    LM_CHECK_OK(t.parent_of(ShortAddr{addr_of(1)}, p));
    LM_CHECK_EQ(p.value(), k_root_addr);

    // The classic race: A and B, both approved under the root, register each other as parent at
    // the same time on their (still correct) paths. The root grants both (pending), READY arrives
    // in either order: exactly one link is applied, the other is refused and must re-register.
    for (int first = 0; first < 2; ++first) {
        Topology u{ShortAddr{k_root_addr}, RootTerm{1}};
        admit_n(u, 2);
        LM_CHECK_OK(attach(u, 0, k_root_addr, 1, 0, true));
        LM_CHECK_OK(attach(u, 1, k_root_addr, 1, 0, true));
        RouteGrant a;
        RouteGrant b;
        LM_CHECK_OK(attach(u, 0, addr_of(1), 2, 0, false, &a));
        LM_CHECK_OK(attach(u, 1, addr_of(0), 2, 0, false, &b));
        const unsigned lead = static_cast<unsigned>(first);
        const RouteGrant &g1 = lead == 0 ? a : b;
        const RouteGrant &g2 = lead == 0 ? b : a;
        LM_CHECK_OK(u.confirm_ready(dev(lead), RootTerm{1}, g1.revision, 1));
        LM_CHECK(u.confirm_ready(dev(1 - lead), RootTerm{1}, g2.revision, 1) == Status::NoRoute);
        RouteGrant path;
        LM_CHECK_OK(u.path_from_root(ShortAddr{addr_of(lead)}, 1, path));
        LM_CHECK_EQ(path.len, 3); // the leader sits below the other one; the other stays at the root
        LM_CHECK_OK(u.path_from_root(ShortAddr{addr_of(1 - lead)}, 1, path));
        LM_CHECK_EQ(path.len, 2);
    }
}

LM_TEST("topology: address reuse, older generation and full table") {
    Topology t{ShortAddr{k_root_addr}, RootTerm{1}};
    admit_n(t, 3);
    LM_CHECK_OK(attach(t, 0, k_root_addr, 1, 0, true));
    LM_CHECK_OK(attach(t, 1, addr_of(0), 1, 0, true));
    RouteGrant g;
    LM_CHECK_OK(t.path_from_root(ShortAddr{addr_of(1)}, 0, g));
    LM_CHECK_EQ(g.len, 3);
    // Same address, higher membership generation: children lose their approved link.
    LM_CHECK_OK(t.admit(dev(0), ShortAddr{addr_of(0)}, AssignmentGen{1}, MembershipGen{2}));
    LM_CHECK(t.path_from_root(ShortAddr{addr_of(1)}, 0, g) == Status::NoRoute);
    LM_CHECK(t.path_from_root(ShortAddr{addr_of(0)}, 0, g) == Status::NoRoute);
    LM_CHECK(t.admit(dev(0), ShortAddr{addr_of(0)}, AssignmentGen{1}, MembershipGen{1}) == Status::Conflict);
    // Another device on the address, and one device on two addresses.
    LM_CHECK_OK(t.admit(dev(50), ShortAddr{addr_of(0)}, AssignmentGen{1}, MembershipGen{1}));
    LM_CHECK(t.admit(dev(50), ShortAddr{addr_of(30)}, AssignmentGen{1}, MembershipGen{1}) == Status::Conflict);
    LM_CHECK(t.admit(dev(51), ShortAddr{k_root_addr}, AssignmentGen{1}, MembershipGen{1}) ==
             Status::InvalidArgument);
    // New term drops every link, keeps membership; the term must grow.
    LM_CHECK_OK(attach(t, 2, k_root_addr, 1, 0, true));
    LM_CHECK(t.begin_term(RootTerm{1}) == Status::Conflict);
    LM_CHECK_OK(t.begin_term(RootTerm{2}));
    LM_CHECK(t.path_from_root(ShortAddr{addr_of(2)}, 0, g) == Status::NoRoute);
    LM_CHECK_OK(attach(t, 2, k_root_addr, 1, 0, true)); // sequence restarts per term
    // Table full: 64 members, the 65th is NoCapacity, and removal frees a slot.
    Topology full{ShortAddr{k_root_addr}, RootTerm{1}};
    admit_n(full, root::k_max_members);
    LM_CHECK(full.admit(dev(500), ShortAddr{900}, AssignmentGen{1}, MembershipGen{1}) == Status::NoCapacity);
    LM_CHECK_OK(full.remove(ShortAddr{addr_of(7)}));
    LM_CHECK_OK(full.admit(dev(500), ShortAddr{900}, AssignmentGen{1}, MembershipGen{1}));
}

// ---- R03 seeded model ----------------------------------------------------------------------

namespace {

struct Rng {
    uint64_t s;
    uint32_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return static_cast<uint32_t>(s >> 16);
    }
    uint32_t below(uint32_t n) { return n == 0 ? 0 : next() % n; }
    bool chance(uint32_t percent) { return below(100) < percent; }
};

struct Msg {
    enum Kind { Register, Ready } kind = Register;
    unsigned node = 0;
    uint32_t term = 0;
    uint16_t parent = 0;
    uint32_t seq = 0;
    uint32_t revision = 0;
    std::vector<uint16_t> path;
    uint32_t membership = 1;
};

struct Stats {
    unsigned accepted = 0, cycle_or_depth = 0, stale = 0, malformed = 0, conflict = 0, ready_applied = 0;
    unsigned lca_routes = 0;
    unsigned max_depth = 0;
};

// Runs one seed; returns "" or the description of the first violated invariant.
class Model {
  public:
    Model(uint64_t seed, unsigned nodes, Stats &stats)
        : rng_{seed * 2654435761ULL + 0x9E3779B97F4A7C15ULL}, n_(nodes), stats_(stats),
          topo_(ShortAddr{k_root_addr}, RootTerm{1}), term_(1), gen_(nodes, 1), seq_(nodes, 0),
          seen_(nodes) {
        for (unsigned i = 0; i < 4; ++i) {
            rng_.next();
        }
        for (unsigned i = 0; i < n_; ++i) {
            (void)topo_.admit(dev(i), ShortAddr{addr_of(i)}, AssignmentGen{1}, MembershipGen{1});
        }
        deep_bias_ = rng_.chance(50) ? 90 : 10;
        calm_ = rng_.chance(50); // calm seeds churn little, so deep trees can form
    }

    std::string run(unsigned steps) {
        for (step_ = 0; step_ < steps; ++step_) {
            do_step();
            const std::string bad = violation_.empty() ? check() : violation_;
            if (!bad.empty()) {
                return bad;
            }
        }
        return "";
    }
    [[nodiscard]] const std::vector<std::string> &trace() const { return trace_; }
    [[nodiscard]] unsigned step() const { return step_; }

  private:
    void log(const std::string &s) {
        trace_.push_back(std::to_string(step_) + " t=" + std::to_string(now_) + " " + s);
        if (trace_.size() > 60) {
            trace_.erase(trace_.begin());
        }
    }

    void snapshot(unsigned node) {
        RouteGrant g;
        if (topo_.path_from_root(ShortAddr{addr_of(node)}, now_, g) == Status::Ok) {
            auto &v = seen_[node];
            v.emplace_back(g.path.begin(), g.path.begin() + g.len);
            if (v.size() > 6) {
                v.erase(v.begin());
            }
        }
    }

    // Parent choice: uniformly random, biased to the deepest known node to reach depth 20.
    uint16_t pick_parent(unsigned self) {
        if (rng_.chance(8)) {
            return k_root_addr;
        }
        unsigned best = n_;
        std::size_t best_len = 0;
        if (rng_.chance(deep_bias_)) { // the deepest node we have an advertisement for
            for (unsigned i = 0; i < n_; ++i) {
                const auto &v = seen_[i];
                if (i != self && !v.empty() && v.back().size() > best_len) {
                    best = i;
                    best_len = v.back().size();
                }
            }
        }
        if (best == n_) {
            best = rng_.below(n_);
        }
        return best == self ? k_root_addr : addr_of(best);
    }

    // `graft`: move a random attached node (with its subtree) below the deepest node, on the deepest
    // node's current path. Aims at the depth-20 rule for whole subtrees.
    void new_register(bool graft = false) {
        unsigned node = rng_.below(n_);
        for (int tries = 0; tries < 3 && deep_bias_ > 50 && rng_.chance(70); ++tries) { // mostly unattached nodes
            ShortAddr ignore;
            if (topo_.parent_of(ShortAddr{addr_of(node)}, ignore) != Status::Ok) {
                break;
            }
            node = rng_.below(n_);
        }
        uint16_t parent = pick_parent(node);
        if (graft) {
            // The node to move is one that sits on other nodes' advertised paths (has a subtree).
            for (unsigned tries = 0; tries < 6; ++tries) {
                const unsigned cand = rng_.below(n_);
                for (unsigned i = 0; i < n_ && !seen_[cand].empty(); ++i) {
                    const auto &v = seen_[i];
                    if (i != cand && !v.empty() &&
                        std::find(v.back().begin(), v.back().end(), addr_of(cand)) != v.back().end()) {
                        node = cand;
                        tries = 6;
                        break;
                    }
                }
            }
            std::size_t best_len = 0;
            for (unsigned i = 0; i < n_; ++i) {
                const auto &v = seen_[i];
                if (i != node && !v.empty() && v.back().size() > best_len) {
                    parent = addr_of(i);
                    best_len = v.back().size();
                }
            }
        }
        Msg m;
        m.kind = Msg::Register;
        m.node = node;
        m.term = rng_.chance(calm_ ? 1 : 5) ? term_ - (term_ > 1 ? 1U : 0U) : term_;
        m.parent = parent;
        m.seq = !rng_.chance(calm_ ? 3 : 15) ? ++seq_[node] : seq_[node] + (rng_.chance(50) ? 0U : 0xFFFFFFF0U);
        m.membership = gen_[node];
        // The child's belief of the parent's path: usually an old advertisement.
        if (parent == k_root_addr) {
            m.path = {k_root_addr};
        } else {
            const auto &v = seen_[parent - 2];
            RouteGrant cur;
            if ((graft || (deep_bias_ > 50 && rng_.chance(80))) &&
                topo_.path_from_root(ShortAddr{parent}, now_, cur) == Status::Ok) {
                m.path.assign(cur.path.begin(), cur.path.begin() + cur.len); // fresh advertisement
            } else if (v.empty() || rng_.chance(15)) {
                m.path = seq_path(k_root_addr, 1 + rng_.below(4)); // guess
            } else {
                m.path = rng_.chance(35) ? v.back() : v[rng_.below(static_cast<uint32_t>(v.size()))];
            }
        }
        if (rng_.chance(calm_ ? 1 : 6)) { // corrupt: duplicate, self, or over-long
            const uint32_t k = rng_.below(3);
            if (k == 0 && m.path.size() > 1) {
                m.path.push_back(m.path[1]);
            } else if (k == 1) {
                m.path.insert(m.path.begin() + 1, addr_of(node));
            } else {
                m.path.resize(std::min<std::size_t>(30, m.path.size() + 12), 7);
            }
        }
        m.path.push_back(addr_of(node)); // parent path + self
        // Duplicate/parent mismatch bookkeeping: the request's parent is whatever precedes self.
        if (m.path.size() >= 2 && !rng_.chance(3)) {
            m.parent = m.path[m.path.size() - 2];
        }
        log("send REGISTER node=" + std::to_string(node) + " parent=" + std::to_string(m.parent) +
            " seq=" + std::to_string(m.seq) + " term=" + std::to_string(m.term));
        net_.push_back(std::move(m));
    }

    void deliver() {
        if (net_.empty()) {
            return;
        }
        const std::size_t i = rng_.below(static_cast<uint32_t>(net_.size()));
        Msg m = net_[i];
        if (!rng_.chance(12)) { // otherwise the copy stays: duplicate delivery later
            net_.erase(net_.begin() + static_cast<std::ptrdiff_t>(i));
        }
        if (rng_.chance(10)) {
            log("lost message");
            return;
        }
        if (m.kind == Msg::Register) {
            RouteRequest rq;
            rq.device = dev(m.node);
            rq.assignment = AssignmentGen{1};
            rq.membership = MembershipGen{m.membership};
            rq.term = RootTerm{m.term};
            rq.parent = ShortAddr{m.parent};
            rq.candidate_path = m.path.data();
            rq.candidate_len = m.path.size();
            rq.request_sequence = m.seq;
            RouteGrant g;
            const Status st = topo_.register_route(rq, now_, g);
            log("REGISTER node=" + std::to_string(m.node) + " -> " + std::string(status_name(st)));
            switch (st) {
            case Status::Ok:
                ++stats_.accepted;
                break;
            case Status::Conflict:
                ++stats_.conflict;
                break;
            case Status::NoRoute:
                ++stats_.stale;
                break;
            default:
                ++stats_.malformed;
                break;
            }
            if (st == Status::Ok) { // ACK to the node, possibly delayed/duplicated/lost
                Msg r;
                r.kind = Msg::Ready;
                r.node = m.node;
                r.term = m.term;
                r.revision = g.revision.value();
                r.path.assign(g.path.begin(), g.path.begin() + g.len); // what the node will apply
                if (!rng_.chance(10)) {
                    net_.push_back(std::move(r));
                }
            }
        } else {
            const Status st = topo_.confirm_ready(dev(m.node), RootTerm{m.term},
                                                  PathRevision{m.revision}, now_);
            log("READY node=" + std::to_string(m.node) + " rev=" + std::to_string(m.revision) +
                " -> " + std::string(status_name(st)));
            stats_.ready_applied += st == Status::Ok ? 1U : 0U;
            RouteGrant now_path;
            if (st == Status::Ok &&
                topo_.path_from_root(ShortAddr{addr_of(m.node)}, now_, now_path) == Status::Ok &&
                !std::equal(m.path.begin(), m.path.end(), now_path.path.begin(),
                            now_path.path.begin() + now_path.len)) {
                violation_ = "READY applied but the approved path differs from the ACKed one, node " +
                             std::to_string(m.node);
            }
            snapshot(m.node);
        }
    }

    void do_step() {
        now_ += rng_.chance(calm_ ? 0 : 2) ? 200000 + rng_.below(100000) : rng_.below(calm_ ? 200 : 3000);
        uint32_t r = rng_.below(100);
        if (calm_ && r >= 91 && r < 98) {
            r = 30 + r % 48; // no address reuse/removal in calm seeds; expiry stays possible
        }
        if (deep_bias_ > 50 && step_ > 1200 && rng_.chance(5)) {
            new_register(true);
        } else if (r < 30) {
            new_register();
        } else if (r < 78) {
            deliver();
        } else if (r < 86) {
            const unsigned node = rng_.below(n_);
            RouteGrant g;
            const Status st = topo_.renew(dev(node), now_, g);
            log("RENEW node=" + std::to_string(node) + " -> " + std::string(status_name(st)));
        } else if (r < 91) {
            topo_.expire(now_);
            log("EXPIRE");
        } else if (r < 96) {
            const unsigned node = rng_.below(n_); // address reuse: a newer membership generation
            ++gen_[node];
            const Status st = topo_.admit(dev(node), ShortAddr{addr_of(node)}, AssignmentGen{1},
                                          MembershipGen{gen_[node]});
            log("REUSE addr=" + std::to_string(addr_of(node)) + " -> " + std::string(status_name(st)));
            seen_[node].clear();
        } else if (r < 98) {
            const unsigned node = rng_.below(n_);
            const Status st = topo_.remove(ShortAddr{addr_of(node)});
            log("REMOVE addr=" + std::to_string(addr_of(node)) + " -> " + std::string(status_name(st)));
            if (st == Status::Ok) { // the ledger re-admits it later as a fresh member
                (void)topo_.admit(dev(node), ShortAddr{addr_of(node)}, AssignmentGen{1},
                                  MembershipGen{gen_[node]});
                seen_[node].clear();
            }
        } else if (rng_.chance(40)) {
            const Status st = topo_.begin_term(RootTerm{term_ + 1});
            if (st == Status::Ok) {
                ++term_;
                std::fill(seq_.begin(), seq_.end(), 0U);
            }
            log("NEW TERM " + std::to_string(term_));
        }
        if (net_.size() > 200) {
            net_.erase(net_.begin(), net_.begin() + 100);
        }
    }

    // Tree invariants read only through the public API.
    std::string check() {
        std::vector<int> parent(n_, -1); // node index of the approved parent, -2 = root
        std::vector<char> active(n_, 0);
        for (unsigned i = 0; i < n_; ++i) {
            ShortAddr p;
            if (topo_.parent_of(ShortAddr{addr_of(i)}, p) == Status::Ok) {
                active[i] = 1;
                parent[i] = p.value() == k_root_addr ? -2 : static_cast<int>(p.value()) - 2;
                if (parent[i] >= static_cast<int>(n_) || parent[i] == static_cast<int>(i)) {
                    return "parent out of range or self for node " + std::to_string(i);
                }
            }
        }
        for (unsigned i = 0; i < n_; ++i) {
            if (!active[i]) {
                continue;
            }
            unsigned depth = 0; // walk to the root: no cycle, depth <= 20
            int cur = static_cast<int>(i);
            while (cur != -2 && depth <= 21) {
                if (cur == -1 || !active[static_cast<unsigned>(cur)]) {
                    break; // detached subtree (an ancestor lost its link): no path, still no loop
                }
                cur = parent[static_cast<unsigned>(cur)];
                ++depth;
            }
            stats_.max_depth = std::max(stats_.max_depth, depth);
            if (depth > 20) {
                return "cycle or depth > 20 at node " + std::to_string(i);
            }
            RouteGrant g;
            const Status st = topo_.path_from_root(ShortAddr{addr_of(i)}, now_, g);
            if (st == Status::Ok) {
                if (g.len != depth + 1 || g.len > 21 || g.path[0] != k_root_addr ||
                    g.path[g.len - 1U] != addr_of(i)) {
                    return "canonical path shape wrong for node " + std::to_string(i);
                }
                for (std::size_t a = 0; a < g.len; ++a) {
                    for (std::size_t b = a + 1; b < g.len; ++b) {
                        if (g.path[a] == g.path[b]) {
                            return "duplicate address in canonical path of " + std::to_string(i);
                        }
                    }
                }
            }
        }
        // Source routes between random pairs are simple, <= 40 and walkable by the forwarder.
        for (int k = 0; k < 3; ++k) {
            const unsigned a = rng_.below(n_ + 1);
            const unsigned b = rng_.below(n_ + 1);
            const uint16_t sa = a == n_ ? k_root_addr : addr_of(a);
            const uint16_t sb = b == n_ ? k_root_addr : addr_of(b);
            SourceRoute r;
            if (topo_.route_between(ShortAddr{sa}, ShortAddr{sb}, now_, r) != Status::Ok) {
                continue;
            }
            ++stats_.lca_routes;
            std::vector<uint16_t> path(r.path.begin(), r.path.begin() + r.len);
            if (r.len < 1 || r.len > 40 || path.back() != sb ||
                wire::validate_simple_path(sa, path.data(), path.size()) != Status::Ok) {
                return "source route not simple/bounded " + std::to_string(sa) + "->" + std::to_string(sb);
            }
            const int fwd = walk(make_header(sa, path, term_), term_);
            if (fwd != static_cast<int>(r.len) - 1) {
                return "forwarder rejected the tree route " + std::to_string(sa) + "->" + std::to_string(sb) +
                       " code " + std::to_string(fwd);
            }
            // Each hop is a tree edge.
            uint16_t prev = sa;
            for (uint16_t hop : path) {
                ShortAddr pa;
                const bool up = topo_.parent_of(ShortAddr{prev}, pa) == Status::Ok && pa.value() == hop;
                const bool down = topo_.parent_of(ShortAddr{hop}, pa) == Status::Ok && pa.value() == prev;
                if (!up && !down) {
                    return "route hop is not a tree edge " + std::to_string(prev) + "->" + std::to_string(hop);
                }
                prev = hop;
            }
        }
        return "";
    }

    Rng rng_;
    unsigned n_;
    Stats &stats_;
    Topology topo_;
    uint32_t term_;
    std::vector<uint32_t> gen_;
    std::vector<uint32_t> seq_;
    std::vector<std::vector<std::vector<uint16_t>>> seen_;
    std::vector<Msg> net_;
    std::vector<std::string> trace_;
    uint64_t now_ = 1000;
    uint32_t deep_bias_ = 10;
    bool calm_ = false;
    unsigned step_ = 0;
    std::string violation_;
};

// Shrinks the node count for a failing seed and prints the trace of the smallest failing run.
void report_failure(uint64_t seed, unsigned nodes, unsigned steps, const std::string &why) {
    unsigned best = nodes;
    std::string best_why = why;
    std::vector<std::string> trace;
    unsigned fail_step = 0;
    for (unsigned n = nodes; n >= 2; --n) {
        Stats s;
        Model m(seed, n, s);
        const std::string w = m.run(steps);
        if (!w.empty()) {
            best = n;
            best_why = w;
            trace = m.trace();
            fail_step = m.step();
        }
    }
    std::fprintf(stderr, "R03 COUNTEREXAMPLE seed=%llu nodes=%u (shrunk from %u) failing step=%u\n  %s\n",
                 static_cast<unsigned long long>(seed), best, nodes, fail_step, best_why.c_str());
    for (const auto &line : trace) {
        std::fprintf(stderr, "    %s\n", line.c_str());
    }
    lmtest::fail(__FILE__, __LINE__, "R03 model invariant violated, seed " + std::to_string(seed));
}

} // namespace

LM_TEST("R03 seeded model: stale/reordered/duplicated registers keep the approved tree simple") {
    const char *one = std::getenv("LM_ROUTE_SEED");
    const char *count = std::getenv("LM_ROUTE_SEEDS");
    const uint64_t first = one != nullptr ? std::strtoull(one, nullptr, 10) : 1;
    const uint64_t seeds = one != nullptr ? 1 : (count != nullptr ? std::strtoull(count, nullptr, 10) : 150);
    constexpr unsigned k_steps = 2500;
    Stats total;
    for (uint64_t seed = first; seed < first + seeds; ++seed) {
        Rng pick{seed * 7919 + 13};
        const unsigned nodes = 4 + pick.below(45); // 4..48 members; even seeds get the larger sizes
        const unsigned nodes_used = seed % 2 == 0 ? std::max(nodes, 30U) : nodes;
        Stats st;
        Model m(seed, nodes_used, st);
        const std::string why = m.run(k_steps);
        if (!why.empty()) {
            report_failure(seed, nodes_used, k_steps, why);
            return;
        }
        total.accepted += st.accepted;
        total.cycle_or_depth += st.cycle_or_depth;
        total.stale += st.stale;
        total.malformed += st.malformed;
        total.conflict += st.conflict;
        total.ready_applied += st.ready_applied;
        total.lca_routes += st.lca_routes;
        total.max_depth = std::max(total.max_depth, st.max_depth);
    }
    std::printf("  R03 seeds %llu..%llu x %u steps: accepted=%u applied=%u stale=%u conflict(cycle/depth/seq)=%u "
                "malformed=%u tree-routes-walked=%u max-depth=%u\n",
                static_cast<unsigned long long>(first), static_cast<unsigned long long>(first + seeds - 1),
                k_steps, total.accepted, total.ready_applied, total.stale, total.conflict,
                total.malformed, total.lca_routes, total.max_depth);
    if (one == nullptr) { // the exploration must actually reach the guarded cases
        LM_CHECK(total.ready_applied > 1000);
        LM_CHECK(total.conflict > 0);
        LM_CHECK(total.stale > 0);
        LM_CHECK(total.lca_routes > 1000);
        LM_CHECK(total.max_depth >= 15); // deep trees really formed (the 20/21 edge is the topology unit test)
    }
}

LM_TEST_MAIN()
