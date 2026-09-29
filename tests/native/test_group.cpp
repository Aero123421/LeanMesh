// GROUP slice (S15): GroupSnapshotV2 pages (token, hash, generations), fan-out from the origin through
// ordinary unicast sends, per-target current outcomes, cancel, a snapshot that stays fixed while the
// group and its members change. Real lm_context + Engine per node on simulated ports; credentials from
// the TEST-ONLY fleet issuer; every session, page and record goes through the real core. "sim" results
// are protocol-bench numbers (virtual time, no RF), never hardware evidence.
//
// Topology (tree, so no node has more than 16 neighbours): root 0, relays 1..R directly under it, the
// leaves spread under the relays. The root's ledger is loaded with the members as ACTIVE entries (the
// members are factory-provisioned with generation 1/1 and address = slot + 2, exactly the entry).
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <vector>

#include "capi/context.hpp"
#include "core/wire/cbor.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_provision.hpp"
#include "port/sim/sim_world.hpp"
#include "security/crypto.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

using Bytes = std::vector<uint8_t>;

struct GNet {
    // parent[i] < i is the node i hangs under (node 0 is the root). Every non-root node is a provisioned
    // member and is listed ACTIVE by the root's provisioning (SEC-D2; generation 1/1, address = slot + 2).
    explicit GNet(const std::vector<int> &parents, uint64_t seed = 61)
        : n(static_cast<unsigned>(parents.size())), net(seed), world(WorldOptions{seed, 0}) {
        std::set<int> has_child;
        for (int p : parents) {
            has_child.insert(p);
        }
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : (has_child.count(static_cast<int>(i)) != 0 ? Role::Relay : Role::Leaf);
            o.mesh = true;
            (void)world.add_node(o);
            world.node(static_cast<uint16_t>(i)).jobs.latency_us = 2000;
            kits.push_back(i == 0 ? net.make_root() : net.make_node(i + 1, static_cast<uint16_t>(i + 1)));
        }
        for (unsigned i = 1; i < n; ++i) {
            LinkParams p;
            p.up = true;
            world.set_link(static_cast<uint16_t>(parents[i]), static_cast<uint16_t>(i), p);
        }
        for (unsigned i = 0; i < n; ++i) {
            LM_CHECK_OK(fleet::provision(node(i).store, net, kits[i]));
        }
    }
    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }
    std::set<unsigned> absent; // nodes that are never started (no route to them ever exists)
    void boot_all() {
        for (unsigned i = 0; i < n; ++i) {
            if (absent.count(i) != 0) {
                continue;
            }
            LM_CHECK_OK(node(i).boot());
            LM_CHECK_EQ(lm_start(node(i).ctx()), LM_STATUS_OK);
        }
    }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    template <class P> bool until(P pred, uint64_t max_ms, uint64_t step_ms = 20) {
        for (uint64_t t = 0; t <= max_ms; t += step_ms) {
            if (pred()) {
                return true;
            }
            run_ms(step_ms);
        }
        return pred();
    }
    [[nodiscard]] uint64_t root_ms() { return node(0).clock.now().to_ms(); }
    void set_time() {
        for (unsigned i = 0; i < n; ++i) {
            if (!node(i).powered()) {
                continue;
            }
            RootTimeBound b;
            b.term = RootTerm{1};
            b.earliest_ms = b.latest_ms = root_ms();
            b.valid = true;
            eng(i).set_root_time(b, node(i).clock.now());
            node(i).notify();
        }
    }
    bool ready() {
        for (unsigned i = 1; i < n; ++i) {
            if (absent.count(i) == 0 && eng(i).mesh().state() != route::Mesh::State::Ready) {
                return false;
            }
        }
        return eng(0).ledger().ready();
    }
    void form(uint64_t limit_ms = 240'000) {
        boot_all();
        set_time();
        const bool ok = until([&] { return ready(); }, limit_ms, 50);
        LM_CHECK(ok);
        set_time();
    }

    // ---- group API (public C ABI) ----
    uint64_t group_set(uint32_t gid, uint64_t expected, const std::vector<unsigned> &members, lm_status_t want = LM_STATUS_OK) {
        std::vector<lm_device_id_t> ids(members.size());
        for (std::size_t k = 0; k < members.size(); ++k) {
            if (members[k] < n) {
                std::memcpy(ids[k].bytes, id(members[k]).bytes.data(), 32);
            } else {
                std::memset(ids[k].bytes, 0xEE, 32); // a device that is not a member of the domain
            }
        }
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_group_set(ctx(0), gid, expected, ids.data(), ids.size(), &op), want);
        node(0).notify();
        return op;
    }
    struct Sent {
        lm_status_t st = LM_STATUS_OK;
        lm_operation_id_t op = 0;
    };
    Sent send(unsigned from, uint32_t gid, uint64_t revision, uint32_t delivery, const Bytes &payload, uint64_t ttl_ms = 120'000,
              uint32_t priority = LM_PRIORITY_NORMAL, uint32_t storage = LM_VOLATILE, uint32_t queue_mode = LM_FIFO) {
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_GROUP;
        rq.destination.group_id = gid;
        rq.destination.group_revision = revision;
        rq.app_port = 100;
        rq.delivery = static_cast<uint8_t>(delivery);
        rq.storage = static_cast<uint8_t>(storage);
        rq.priority = static_cast<uint8_t>(priority);
        rq.queue_mode = static_cast<uint8_t>(queue_mode);
        rq.coalesce_key = queue_mode == LM_LATEST ? 1 : 0;
        rq.root_term = 1;
        rq.expires_root_ms = root_ms() + ttl_ms;
        Sent s;
        s.st = lm_send(ctx(from), &rq, payload.data(), payload.size(), &s.op);
        node(from).notify();
        return s;
    }
    lm_operation_t op(unsigned i, lm_operation_id_t o) {
        lm_operation_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_get_operation(ctx(i), o, &r), LM_STATUS_OK);
        return r;
    }
    lm_group_progress_t progress(unsigned i, lm_operation_id_t o) {
        lm_group_progress_t p{};
        p.struct_size = sizeof(p);
        p.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_group_progress(ctx(i), o, &p), LM_STATUS_OK);
        return p;
    }
    // Every target of the snapshot, page by page (16 per call).
    std::vector<lm_group_target_t> targets(unsigned i, lm_operation_id_t o) {
        const lm_group_progress_t p = progress(i, o);
        std::vector<lm_group_target_t> all;
        uint32_t total = 0;
        for (uint32_t off = 0; off < p.total; off += 16) {
            std::array<lm_group_target_t, 16> page{};
            size_t written = 0;
            LM_CHECK_EQ(lm_group_targets(ctx(i), o, p.snapshot_token, off, page.data(), page.size(), &written, &total), LM_STATUS_OK);
            all.insert(all.end(), page.begin(), page.begin() + static_cast<long>(written));
        }
        LM_CHECK_EQ(all.size(), static_cast<std::size_t>(p.total));
        return all;
    }
    static uint32_t sum(const lm_group_progress_t &p) {
        return p.pending + p.submitted + p.received + p.applied + p.rejected + p.expired + p.cancelled + p.indeterminate + p.superseded;
    }
    // The takes of the applications: every MESSAGE event on node i, optionally reported APPLIED.
    unsigned take_messages(unsigned i, bool report) {
        unsigned taken = 0;
        for (;;) {
            lm_event_t ev{};
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            std::array<uint8_t, 600> buf{};
            size_t req = 0;
            if (lm_next_event(ctx(i), &ev, buf.data(), buf.size(), &req) != LM_STATUS_OK) {
                return taken;
            }
            if (ev.kind != LM_EVENT_MESSAGE) {
                continue;
            }
            ++taken;
            if (report) {
                lm_message_ref_t ref{};
                ref.origin = ev.peer;
                ref.assignment_generation = ev.origin_assignment_generation;
                ref.id = ev.message_id;
                std::memcpy(ref.intent_hash, ev.intent_hash, 32);
                LM_CHECK_EQ(lm_report_application_result(ctx(i), &ref, LM_OUTCOME_APPLIED, nullptr, 0, nullptr), LM_STATUS_OK);
            }
        }
    }

    unsigned n;
    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;
};

// root 0; relays 1..r; leaves r+1..n-1 spread round-robin under the relays.
std::vector<int> tree(unsigned relays, unsigned leaves) {
    std::vector<int> p{-1};
    for (unsigned r = 1; r <= relays; ++r) {
        p.push_back(0);
    }
    for (unsigned l = 0; l < leaves; ++l) {
        p.push_back(static_cast<int>(1 + l % relays));
    }
    return p;
}

[[maybe_unused]] // root 0 with `members` leaves directly under it (a leave reaches the root only from a neighbour of it)
std::vector<int> star(unsigned members) {
    std::vector<int> p{-1};
    p.insert(p.end(), members, 0);
    return p;
}

std::vector<unsigned> range(unsigned a, unsigned b) {
    std::vector<unsigned> v;
    for (unsigned i = a; i < b; ++i) {
        v.push_back(i);
    }
    return v;
}

// Independent computation of snapshot_hash: SHA-256 over the deterministic CBOR array of docs/22 §2.
Sha256Digest expected_hash(GNet &g, unsigned origin, uint32_t gid, uint64_t revision, const uint8_t *token,
                           const std::vector<lm_group_target_t> &t) {
    std::vector<uint8_t> buf(64 * 60 + 128);
    wire::CborWriter w{MutByteView{buf.data(), buf.size()}};
    w.array(6);
    w.bytes(g.net.domain.view());
    w.uint(gid);
    w.uint(revision);
    w.bytes(ByteView{token, 16});
    w.bytes(g.id(origin).view());
    w.array(t.size());
    for (const auto &x : t) {
        w.array(3);
        w.bytes(ByteView{x.device.bytes, 32});
        w.uint(x.assignment_generation);
        w.uint(x.membership_generation);
    }
    LM_CHECK_OK(w.finish());
    Sha256Digest d{};
    LM_CHECK_OK(sec::sha256(w.written(), d));
    return d;
}

} // namespace

LM_TEST("D11 sim (small): a member that is not the root fetches the snapshot from the root and fans out") {
    // root 0, relay 1, leaves 2 (origin), 3, 4
    GNet n(tree(1, 3));
    n.form();
    n.group_set(7, 0, {1, 3, 4});
    const Bytes body(40, 0x5A);
    const auto s = n.send(2, 7, 1, LM_RECEIVED, body);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(2, s.op).phase == 3; }, 60'000));
    const lm_operation_t o = n.op(2, s.op);
    LM_CHECK_EQ(o.outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    const lm_group_progress_t p = n.progress(2, s.op);
    LM_CHECK_EQ(p.total, 3u);
    LM_CHECK_EQ(p.received, 3u);
    LM_CHECK_EQ(GNet::sum(p), p.total);
    const auto t = n.targets(2, s.op);
    const Sha256Digest h = expected_hash(n, 2, 7, 1, p.snapshot_token, t);
    LM_CHECK(std::memcmp(h.data(), p.snapshot_hash, 32) == 0);
    for (const auto &x : t) {
        LM_CHECK_EQ(x.outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
        LM_CHECK_EQ(x.phase, static_cast<uint32_t>(LM_TARGET_FINAL));
    }
    std::printf("  pages served %llu fetched %llu\n", (unsigned long long)n.eng(0).group().stats().pages_served,
                (unsigned long long)n.eng(2).group().stats().pages_fetched);
    LM_CHECK_EQ(n.eng(0).group().stats().pages_served, 1ull);
    LM_CHECK_EQ(n.eng(2).group().stats().pages_fetched, 1ull);
    LM_CHECK_EQ(n.take_messages(1, false), 1u);
    LM_CHECK_EQ(n.take_messages(3, false), 1u);
    LM_CHECK_EQ(n.take_messages(4, false), 1u);
    LM_CHECK_EQ(n.take_messages(0, false), 0u); // D12: the root only served the pages, it never saw the body
    LM_CHECK_EQ(n.eng(0).delivery().stats().rx_data, 0ull);
    // Another member cannot read this snapshot: its token is bound to the origin (docs/22 §2).
    const uint64_t served = n.eng(0).group().stats().pages_served;
    std::array<uint8_t, 64> data{};
    wire::CborWriter d{MutByteView{data}};
    d.array(4);
    d.uint(7);
    d.uint(1);
    d.uint(0);
    d.bytes(ByteView{p.snapshot_token, 16});
    LM_CHECK_OK(d.finish());
    wire::ControlBody cb;
    cb.type = group::k_type_request;
    cb.request_id.fill(0x33);
    cb.domain = n.net.domain.bytes;
    cb.issuer = n.id(3).bytes;
    cb.data = d.written();
    std::array<uint8_t, 160> req_body{};
    std::size_t blen = 0;
    LM_CHECK_OK(wire::encode_control_body(cb, MutByteView{req_body.data(), req_body.size()}, blen));
    delivery::ControlSendRequest cr;
    cr.dest = n.id(0);
    cr.root_term = 1;
    cr.expires_root_ms = n.root_ms() + 30000;
    Command cmd;
    cmd.kind = CommandKind::SendControl;
    cmd.request = &cr;
    cmd.request_size = sizeof(cr);
    cmd.payload = ByteView{req_body.data(), blen};
    LM_CHECK_EQ(n.eng(3).execute(cmd, n.node(3).clock.now()).status, Status::Ok);
    n.node(3).notify();
    n.run_ms(10'000);
    LM_CHECK_EQ(n.eng(0).group().stats().pages_served, served);
}

LM_TEST("D11 GS03 sim: registry rules and a snapshot the root does not know") {
    GNet n(tree(1, 3));
    n.form();
    n.group_set(1, 5, {1, 2}, LM_STATUS_CONFLICT);           // a new group starts at revision 0
    n.group_set(1, 0, {1, 2, 2}, LM_STATUS_INVALID_ARGUMENT); // one member twice
    n.group_set(1, 0, {1, 2, 9}, LM_STATUS_NOT_FOUND);        // not a member of the domain
    n.group_set(1, 0, {1, 2});
    n.group_set(1, 0, {1, 2, 3}, LM_STATUS_CONFLICT);          // stale expected revision
    n.group_set(1, 1, {1, 2, 3});
    for (uint32_t g = 2; g <= 8; ++g) {
        n.group_set(g, 0, {});                                 // an empty group is a group
    }
    n.group_set(9, 0, {1}, LM_STATUS_NO_CAPACITY);             // at most 8 groups
    {
        std::vector<lm_device_id_t> id(1);
        std::memcpy(id[0].bytes, n.id(1).bytes.data(), 32);
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_group_set(n.ctx(2), 1, 2, id.data(), 1, &op), LM_STATUS_ROLE_NOT_ALLOWED); // only the root manages groups
    }
    // GS09 is not built: a DURABLE (or LATEST) group send is refused as UNSUPPORTED before anything exists.
    LM_CHECK_EQ(n.send(0, 1, 2, LM_RECEIVED, Bytes(8, 1), 120'000, LM_PRIORITY_NORMAL, LM_DURABLE).st, LM_STATUS_UNSUPPORTED);
    LM_CHECK_EQ(n.send(0, 1, 2, LM_BEST_EFFORT, Bytes(8, 1), 120'000, LM_PRIORITY_NORMAL, LM_VOLATILE, LM_LATEST).st, LM_STATUS_UNSUPPORTED);
    // An empty group is complete at once (total 0), and it is not "all".
    const auto e = n.send(0, 4, 1, LM_RECEIVED, Bytes(8, 1));
    LM_CHECK_EQ(e.st, LM_STATUS_OK);
    LM_CHECK_EQ(n.op(0, e.op).phase, 3u);
    LM_CHECK_EQ(n.op(0, e.op).outcome, static_cast<uint32_t>(LM_OUTCOME_PARTIAL));
    LM_CHECK_EQ(n.progress(0, e.op).total, 0u);
    // Unknown revision at the root: refused at once. At a member: no page ever comes; it ends REJECTED (ROOT_UNAVAILABLE).
    LM_CHECK_EQ(n.send(0, 1, 1, LM_RECEIVED, Bytes(8, 1)).st, LM_STATUS_CONFLICT);
    LM_CHECK_EQ(n.send(0, 77, 1, LM_RECEIVED, Bytes(8, 1)).st, LM_STATUS_NOT_FOUND);
    const auto m = n.send(2, 1, 1, LM_RECEIVED, Bytes(8, 1), 120'000);
    LM_CHECK_EQ(m.st, LM_STATUS_OK);
    LM_CHECK_EQ(n.progress(2, m.op).total, 0u); // fetching: no set yet
    LM_CHECK(n.until([&] { return n.op(2, m.op).phase == 3; }, 30'000));
    LM_CHECK_EQ(n.op(2, m.op).outcome, static_cast<uint32_t>(LM_OUTCOME_REJECTED));
    LM_CHECK_EQ(n.op(2, m.op).reason, static_cast<uint32_t>(LM_STATUS_ROOT_UNAVAILABLE));
    // A member cancels while it still fetches: nothing was sent.
    const auto c = n.send(2, 1, 2, LM_RECEIVED, Bytes(8, 1), 120'000);
    LM_CHECK_EQ(c.st, LM_STATUS_OK);
    LM_CHECK_EQ(lm_cancel(n.ctx(2), c.op), LM_STATUS_OK);
    LM_CHECK_EQ(n.op(2, c.op).outcome, static_cast<uint32_t>(LM_OUTCOME_CANCELLED_NOT_SENT));
    // One operation at a time on a leaf (profile group_operations = 1); four on the root (GS08).
    const auto a1 = n.send(0, 1, 2, LM_RECEIVED, Bytes(500, 1), 120'000);
    LM_CHECK_EQ(a1.st, LM_STATUS_OK);
    const auto a2 = n.send(0, 1, 2, LM_RECEIVED, Bytes(500, 2), 120'000);
    const auto a3 = n.send(0, 1, 2, LM_RECEIVED, Bytes(500, 3), 120'000);
    const auto a4 = n.send(0, 1, 2, LM_RECEIVED, Bytes(500, 4), 120'000);
    const auto a5 = n.send(0, 1, 2, LM_RECEIVED, Bytes(500, 5), 120'000);
    LM_CHECK(a2.st == LM_STATUS_OK && a3.st == LM_STATUS_OK && a4.st == LM_STATUS_OK);
    LM_CHECK_EQ(a5.st, LM_STATUS_NO_CAPACITY); // before acceptance: no operation exists
}

namespace {
// Runs until the group operation is final, sampling the invariants at every step: the outcomes always
// add up to the total (GS10), at most four targets are in flight (docs/22 §4).
struct Watch {
    unsigned max_live = 0;
    bool sums_ok = true;
    unsigned samples = 0;
};
bool run_to_final(GNet &n, unsigned origin, lm_operation_id_t op, Watch &w, uint64_t limit_ms, uint64_t step_ms = 20) {
    return n.until(
        [&] {
            const lm_group_progress_t p = n.progress(origin, op);
            w.sums_ok = w.sums_ok && GNet::sum(p) == p.total;
            ++w.samples;
            for (std::size_t k = 0; k < group::k_ops; ++k) {
                const group::Op *g = n.eng(origin).group().op_at(k);
                w.max_live = g->kind == group::Op::Kind::Own && g->id == op ? std::max<unsigned>(w.max_live, g->live) : w.max_live;
            }
            return n.op(origin, op).phase == 3;
        },
        limit_ms, step_ms);
}
} // namespace

LM_TEST("D11 sim: 64 targets from a member that is not the root; four pages, four in flight, one target leaves mid-way") {
    GNet n(tree(8, 56)); // 8 relays, 56 leaves = 64 members; node 9 is the origin and a member of the group itself
    n.form(600'000);
    std::vector<unsigned> members;
    for (unsigned i = 1; i < n.n; ++i) {
        members.push_back(i);
    }
    LM_CHECK_EQ(members.size(), 64u);
    n.group_set(1, 0, members);
    const Bytes body(512, 0xA7);
    const auto s = n.send(9, 1, 1, LM_RECEIVED, body, 200'000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.progress(9, s.op).total == 64; }, 60'000));
    const auto snap = n.targets(9, s.op);
    LM_CHECK_EQ(snap.size(), 64u);
    for (std::size_t i = 1; i < snap.size(); ++i) { // sorted, unique
        LM_CHECK(std::memcmp(snap[i - 1].device.bytes, snap[i].device.bytes, 32) < 0);
    }
    // The last target of the snapshot (not the origin) leaves the network before the fan-out gets to it.
    unsigned leaver = 0;
    for (std::size_t k = snap.size(); k-- > 0 && leaver == 0;) {
        for (unsigned i = 1; i < n.n; ++i) {
            leaver = i != 9 && std::memcmp(n.id(i).bytes.data(), snap[k].device.bytes, 32) == 0 ? i : leaver;
        }
    }
    LM_CHECK(leaver != 0);
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(leaver), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    n.node(leaver).notify();
    Watch w;
    const uint64_t t0 = n.world.now_us();
    LM_CHECK(run_to_final(n, 9, s.op, w, 260'000));
    std::printf("  D11-sim: 64 targets final after %llu ms (virtual), max in flight %u, %u samples\n",
                (unsigned long long)((n.world.now_us() - t0) / 1000), w.max_live, w.samples);
    LM_CHECK(w.sums_ok);
    LM_CHECK(w.max_live <= 4);
    const lm_group_progress_t p = n.progress(9, s.op);
    LM_CHECK_EQ(p.total, 64u);
    LM_CHECK_EQ(p.received, 62u);
    LM_CHECK_EQ(p.rejected + p.expired, 2u); // the origin itself (no loopback) and the target that left
    LM_CHECK_EQ(n.op(9, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_PARTIAL));
    const Sha256Digest h = expected_hash(n, 9, 1, 1, p.snapshot_token, n.targets(9, s.op));
    LM_CHECK(std::memcmp(h.data(), p.snapshot_hash, 32) == 0);
    LM_CHECK_EQ(n.eng(9).group().stats().pages_fetched, 4ull);
    LM_CHECK_EQ(n.eng(0).delivery().stats().rx_data, 0ull);
}

namespace {
// One step of every application: takes each message and reports it APPLIED (a device that does its job).
void apps_apply(GNet &n, const std::set<unsigned> &slow = {}) {
    for (unsigned i = 1; i < n.n; ++i) {
        if (slow.count(i) == 0) {
            (void)n.take_messages(i, true);
        }
    }
}
const group::Op *own(GNet &n, unsigned i, uint64_t op) {
    for (std::size_t k = 0; k < group::k_ops; ++k) {
        const group::Op *g = n.eng(i).group().op_at(k);
        if (g->kind == group::Op::Kind::Own && g->id == op) {
            return g;
        }
    }
    return nullptr;
}
} // namespace

LM_TEST("GS07 GS10 sim: the root fans out 64 APPLIED targets, cancel mid-way keeps the sent ones open, a late APPLIED improves an unknown result") {
    GNet n(tree(8, 56));
    n.form(600'000);
    n.group_set(3, 0, range(1, 65));
    const auto s = n.send(0, 3, 1, LM_APPLIED, Bytes(300, 0x11), 400'000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    Watch w;
    // Applications answer (two of them are slow) while the fan-out runs; it is cancelled with targets still to go
    // and with the two slow devices holding a message they have not yet reported.
    std::set<unsigned> slow; // the two first targets of the snapshot: dispatched first
    for (unsigned k = 0; k < 2; ++k) {
        for (unsigned i = 1; i < n.n; ++i) {
            if (std::memcmp(n.id(i).bytes.data(), n.targets(0, s.op)[k].device.bytes, 32) == 0) {
                slow.insert(i);
            }
        }
    }
    LM_CHECK_EQ(slow.size(), 2u);
    LM_CHECK(n.until(
        [&] {
            apps_apply(n, slow);
            const lm_group_progress_t p = n.progress(0, s.op);
            w.sums_ok = w.sums_ok && GNet::sum(p) == p.total;
            return p.applied >= 20;
        },
        300'000, 20));
    // GS08: one payload buffer for the operation (never one per target) plus one per child in flight
    LM_CHECK_EQ(n.eng(0).delivery().free_msg_buffers() + 1 + own(n, 0, s.op)->live, k_build_limits.app_messages);
    LM_CHECK_EQ(lm_cancel(n.ctx(0), s.op), LM_STATUS_OK);
    n.node(0).notify();
    // Nothing answers now: what was sent stays open, then ends INDETERMINATE (not "not applied").
    LM_CHECK(n.until([&] { return n.op(0, s.op).phase == 3; }, 60'000, 20));
    const lm_group_progress_t p1 = n.progress(0, s.op);
    LM_CHECK_EQ(GNet::sum(p1), 64u);
    LM_CHECK(p1.cancelled > 20u); // the fan-out was far from done
    LM_CHECK(p1.applied >= 20u);
    LM_CHECK(p1.indeterminate >= 1u); // sent, no result yet: unknown, not failed
    LM_CHECK_EQ(n.op(0, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_PARTIAL));
    // The applications answer late: the unknown results become APPLIED, the revision moves, nothing rolls back.
    for (unsigned i = 1; i < n.n; ++i) { // every device that still holds a message reports it now
        (void)n.take_messages(i, true);
    }
    n.run_ms(5'000);
    const lm_group_progress_t p2 = n.progress(0, s.op);
    std::printf("  GS07: cancelled %u applied %u->%u indeterminate %u->%u late %llu revision %llu->%llu\n", p1.cancelled, p1.applied,
                p2.applied, p1.indeterminate, p2.indeterminate, (unsigned long long)n.eng(0).group().stats().late,
                (unsigned long long)p1.progress_revision, (unsigned long long)p2.progress_revision);
    LM_CHECK_EQ(GNet::sum(p2), 64u);
    LM_CHECK_EQ(p2.cancelled, p1.cancelled);
    LM_CHECK(p2.applied > p1.applied); // a device that had not reported yet does so late
    LM_CHECK_EQ(p2.applied - p1.applied + p2.indeterminate, p1.indeterminate); // upgrades only; nothing rolled back
    LM_CHECK(p2.progress_revision > p1.progress_revision);
    LM_CHECK(w.sums_ok);
    LM_CHECK_EQ(lm_cancel(n.ctx(0), s.op), LM_STATUS_CANCEL_TOO_LATE);
}

LM_TEST("GS02 GS03 D11 sim: the set is fixed at the start; a member that leaves is rejected, not replaced; an edit is a new revision") {
    GNet n(star(12));
    n.form();
    n.group_set(5, 0, range(1, 13));
    const auto s = n.send(0, 5, 1, LM_RECEIVED, Bytes(20, 1), 120'000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    const auto snap = n.targets(0, s.op);
    const lm_group_progress_t p0 = n.progress(0, s.op);
    // node 16 leaves; the group is edited (11 members, revision 2) while the first operation runs
    lm_operation_id_t lop = 0;
    unsigned leaver = 0; // the last target of the snapshot: not dispatched yet
    for (unsigned i = 1; i < n.n; ++i) {
        leaver = std::memcmp(n.id(i).bytes.data(), snap.back().device.bytes, 32) == 0 ? i : leaver;
    }
    LM_CHECK(leaver != 0);
    LM_CHECK_EQ(lm_leave(n.ctx(leaver), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    n.node(leaver).notify();
    n.run_ms(3000);
    LM_CHECK(n.eng(0).ledger().find(n.id(leaver))->state != root::EntryState::Active);
    n.group_set(5, 1, [&] { auto m = range(1, 13); m.erase(std::find(m.begin(), m.end(), leaver)); return m; }());
    Watch w;
    LM_CHECK(run_to_final(n, 0, s.op, w, 120'000));
    const lm_group_progress_t p = n.progress(0, s.op);
    LM_CHECK_EQ(p.total, 12u);
    LM_CHECK(std::memcmp(p.snapshot_hash, p0.snapshot_hash, 32) == 0); // the same set, the same hash
    LM_CHECK(std::memcmp(p.snapshot_token, p0.snapshot_token, 16) == 0);
    LM_CHECK_EQ(p.received, 11u);
    LM_CHECK_EQ(p.rejected + p.expired, 1u);
    const auto t = n.targets(0, s.op);
    std::size_t bad = 0;
    for (std::size_t i = 0; i < t.size(); ++i) {
        LM_CHECK(std::memcmp(t[i].device.bytes, snap[i].device.bytes, 32) == 0);
        if (t[i].outcome != LM_OUTCOME_RECEIVED) {
            std::printf("  target %zu outcome %u reason %u phase %u\n", i, t[i].outcome, t[i].reason, t[i].phase);
            ++bad;
            LM_CHECK(std::memcmp(t[i].device.bytes, n.id(leaver).bytes.data(), 32) == 0);
            LM_CHECK_EQ(t[i].reason, static_cast<uint32_t>(LM_STATUS_TARGET_GENERATION_CHANGED));
        }
    }
    LM_CHECK_EQ(bad, 1u);
    LM_CHECK_EQ(n.take_messages(leaver, false), 0u); // nothing reached the device that left
    // The old revision is refused at once for a new send; the new one has the new set.
    LM_CHECK_EQ(n.send(0, 5, 1, LM_RECEIVED, Bytes(20, 1)).st, LM_STATUS_CONFLICT);
    const auto s2 = n.send(0, 5, 2, LM_RECEIVED, Bytes(20, 2), 120'000);
    LM_CHECK_EQ(s2.st, LM_STATUS_OK);
    LM_CHECK_EQ(n.progress(0, s2.op).total, 11u);
    LM_CHECK(std::memcmp(n.progress(0, s2.op).snapshot_hash, p0.snapshot_hash, 32) != 0);
}

LM_TEST("GS11 sim: targets that cannot be routed step aside (WAIT_ROUTE) and do not starve the others; the partial result is kept") {
    GNet n(tree(4, 12));
    n.absent = {6, 9, 12, 15, 16}; // five members that never come up: their sends wait for a route
    n.form();
    n.group_set(6, 0, range(1, 17));
    const uint64_t t0 = n.world.now_us();
    const auto s = n.send(0, 6, 1, LM_RECEIVED, Bytes(30, 2), 90'000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    Watch w;
    uint64_t live_done_ms = 0;
    LM_CHECK(n.until(
        [&] {
            const lm_group_progress_t p = n.progress(0, s.op);
            w.sums_ok = w.sums_ok && GNet::sum(p) == p.total;
            live_done_ms = p.received == 11 && live_done_ms == 0 ? (n.world.now_us() - t0) / 1000 : live_done_ms;
            return n.op(0, s.op).phase == 3;
        },
        120'000, 20));
    const lm_group_progress_t p = n.progress(0, s.op);
    std::printf("  GS11-sim: 11 reachable targets received after %llu ms, the rest ended at the deadline (parked %llu times)\n",
                (unsigned long long)live_done_ms, (unsigned long long)n.eng(0).group().stats().parked);
    LM_CHECK(w.sums_ok);
    LM_CHECK_EQ(p.received, 11u);
    LM_CHECK_EQ(p.expired, 5u); // never sent: EXPIRED at the deadline, not INDETERMINATE and not a loss
    LM_CHECK(live_done_ms > 0 && live_done_ms < 60'000); // the reachable ones did not wait for the dead ones' deadline
    LM_CHECK(n.eng(0).group().stats().parked > 0);
    LM_CHECK_EQ(n.op(0, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_PARTIAL));
    for (const auto &x : n.targets(0, s.op)) {
        if (x.outcome != LM_OUTCOME_RECEIVED) {
            LM_CHECK_EQ(x.phase, static_cast<uint32_t>(LM_TARGET_FINAL));
        }
    }
}

LM_TEST("serial SEND names a group by a marker value; only that shape is one") {
    const DeviceId d = group::group_dest(0xA1B2C3D4U, 0x0102030405060708ULL);
    uint32_t gid = 0;
    uint64_t rev = 0;
    LM_CHECK(group::is_group_dest(d.view(), gid, rev));
    LM_CHECK_EQ(gid, 0xA1B2C3D4U);
    LM_CHECK_EQ(rev, 0x0102030405060708ULL);
    DeviceId other = d;
    other.bytes[0] = 1; // a value with any other bit set is a DeviceId, never a group
    LM_CHECK(!group::is_group_dest(other.view(), gid, rev));
    other = d;
    other.bytes[31] = 1;
    LM_CHECK(!group::is_group_dest(other.view(), gid, rev));
    LM_CHECK(!group::is_group_dest(group::group_dest(0, 5).view(), gid, rev)); // group 0 does not exist
}

LM_TEST_MAIN()
