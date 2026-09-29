// Link sessions between provisioned sim nodes: real lm_context + Engine on sim ports, credentials
// from the TEST-ONLY fleet issuer, EDHOC purpose 1 + SESSION_BIND through the worker jobs and the
// simulated medium. Acceptance IDs in the test names (docs/IMPLEMENTATION.md §11, S5).
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include "capi/context.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"
#include "security/crypto.hpp"
#include "stack_probe.hpp"
#include "store/record.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

using Bytes = std::vector<uint8_t>;

struct Sinked {
    std::vector<Bytes> got;
    std::vector<bool> dup;
    std::vector<bool> restricted;
    std::vector<DeviceId> from;
    [[nodiscard]] std::size_t fresh() const {
        std::size_t n = 0;
        for (bool d : dup) {
            n += d ? 0 : 1;
        }
        return n;
    }
};

void sink_fn(void *ctx, const link::RxInfo &info, ByteView plain) {
    auto *s = static_cast<Sinked *>(ctx);
    s->got.emplace_back(plain.begin(), plain.end());
    s->dup.push_back(info.duplicate);
    s->restricted.push_back(info.restricted);
    s->from.push_back(info.peer);
}

struct Net {
    // `start` false: the test provisions/boots nodes itself (custom stores).
    explicit Net(unsigned n, uint64_t seed = 11, bool start = true)
        : net(seed), world(WorldOptions{seed, 0}), sinks(n) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            (void)world.add_node(o);
            kits.push_back(i == 0 ? net.make_root() : net.make_node(i, static_cast<uint16_t>(i + 1)));
        }
        world.make_full();
        if (start) {
            for (unsigned i = 0; i < n; ++i) {
                LM_CHECK_OK(fleet::provision(node(i).store, net, kits[i]));
            }
            for (unsigned i = 0; i < n; ++i) {
                boot(static_cast<uint16_t>(i));
            }
            run_ms(20);
            // The root takes part once its ledger is loaded (SEC-D2); other owners may hold its record memory first.
            (void)run_until([&] { return eng(0).ledger().ready(); }, 500);
        }
    }

    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    void boot(uint16_t i) {
        LM_CHECK_OK(world.node(i).boot());
        LM_CHECK_EQ(lm_start(world.node(i).ctx()), LM_STATUS_OK);
        eng(i).link().set_sink(&sink_fn, &sinks[i]);
    }
    void reboot(uint16_t i) {
        world.node(i).power_cut();
        world.node(i).store.power_restore();
        boot(i);
    }
    Engine &eng(uint16_t i) { return world.node(i).ctx()->engine; }
    link::LinkLayer &lnk(uint16_t i) { return eng(i).link(); }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    void run_s(uint64_t s) { run_ms(s * 1000); }
    MonoTime now(uint16_t i) { return world.node(i).clock.now(); }
    const MacAddr &mac(uint16_t i) { return world.node(i).radio.mac(); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }

    Status connect(uint16_t a, uint16_t b, bool replace = false) {
        const Status s = lnk(a).connect(mac(b), now(a), replace);
        world.node(a).notify();
        return s;
    }
    link::Neighbor *nb(uint16_t a, uint16_t b) { return lnk(a).neighbors().find_device(id(b)); }
    bool session(uint16_t a, uint16_t b) {
        link::Neighbor *n = nb(a, b);
        return n != nullptr && n->cur.active;
    }
    // Both ends hold an active session with mirrored SIDs and the same context.
    bool paired(uint16_t a, uint16_t b) {
        link::Neighbor *x = nb(a, b);
        link::Neighbor *y = nb(b, a);
        return x != nullptr && y != nullptr && x->cur.active && y->cur.active &&
               x->cur.rx_sid == y->cur.tx_sid && x->cur.tx_sid == y->cur.rx_sid &&
               x->cur.ctx_hash == y->cur.ctx_hash;
    }
    // Seals `payload` as CONTROL at a and transmits it to b's radio.
    Status send(uint16_t a, uint16_t b, const Bytes &payload, link::SealedFrame *keep = nullptr) {
        link::SealedFrame f;
        LM_TRY(lnk(a).seal(id(b), wire::FrameKind::Control, ByteView{payload.data(), payload.size()}, f,
                           now(a)));
        if (keep != nullptr) {
            *keep = f;
        }
        const Status s = eng(a).transmit(mac(b), f.view(), 0, now(a));
        world.node(a).notify();
        return s;
    }
    // Replays a captured frame at `to` as if `from` had sent it (heard over from's own links).
    void inject(uint16_t from, uint16_t to, const link::SealedFrame &f) {
        world.inject(mac(from), from, mac(to), f.view());
    }
    // Steps in 1 ms until `pred` holds (bounded).
    template <class P> bool run_until(P pred, uint64_t max_ms) {
        for (uint64_t t = 0; t < max_ms; ++t) {
            if (pred()) {
                return true;
            }
            run_ms(1);
        }
        return pred();
    }

    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;
    std::vector<Sinked> sinks;
};

Bytes payload_of(uint8_t seed, std::size_t n = 12) {
    Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) {
        b[i] = static_cast<uint8_t>(seed + i);
    }
    return b;
}

} // namespace

LM_TEST("S5 provisioned nodes load identity and membership at start") {
    Net n(2);
    for (uint16_t i = 0; i < 2; ++i) {
        LM_CHECK(n.eng(i).identity().state() == member::LocalIdentity::State::Ready);
        LM_CHECK(n.eng(i).identity().is_member());
        LM_CHECK(n.eng(i).identity().self() == n.id(i));
    }
}

LM_TEST("S5 link session: EDHOC purpose 1 + SESSION_BIND between two ACTIVE nodes, data both ways once") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    LM_CHECK_EQ(n.lnk(0).stats().hs_completed, 1u);
    LM_CHECK_EQ(n.lnk(1).stats().hs_completed, 1u);
    LM_CHECK(!n.lnk(0).exchange().busy() && !n.lnk(1).exchange().busy());
    // No root time exists yet: the link comes first and the lease is checked once time is known (node 1; the root
    // admits by its ledger and does not count leases, S18-D1).
    LM_CHECK(n.lnk(1).stats().cred_time_uncertain >= 1u);
    LM_CHECK_OK(n.send(1, 0, {1, 2, 3}));
    n.run_ms(50);
    LM_CHECK_OK(n.send(0, 1, {9, 8, 7, 6}));
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[0].got.size(), 1u);
    LM_CHECK(n.sinks[0].got[0] == (Bytes{1, 2, 3}));
    LM_CHECK(n.sinks[0].from[0] == n.id(1));
    LM_CHECK_EQ(n.sinks[1].got.size(), 1u);
    LM_CHECK(n.sinks[1].got[0] == (Bytes{9, 8, 7, 6}));
}

LM_TEST("S02 session context binds full identities, generations and credential hashes") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0)); // node 1 initiates
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    sec::SessionContext ctx;
    ctx.purpose = sec::Purpose::Link;
    ctx.fleet = n.net.fleet.trust().fleet;
    ctx.domain = n.net.domain;
    ctx.initiator = n.id(1);
    ctx.responder = n.id(0);
    ctx.assignment_i = AssignmentGen{1};
    ctx.assignment_r = AssignmentGen{1};
    ctx.membership_i = MembershipGen{1};
    ctx.membership_r = MembershipGen{1};
    LM_CHECK_OK(sec::sha256(ByteView{n.kits[1].member_cose.data(), n.kits[1].member_cose.size()},
                            ctx.credential_hash_i));
    LM_CHECK_OK(sec::sha256(ByteView{n.kits[0].member_cose.data(), n.kits[0].member_cose.size()},
                            ctx.credential_hash_r));
    Sha256Digest expect{};
    LM_CHECK_OK(sec::context_hash(ctx, expect));
    LM_CHECK(n.nb(0, 1)->cur.ctx_hash == expect);
    LM_CHECK(n.nb(1, 0)->cur.ctx_hash == expect);
    // A different purpose, domain or generation is a different context and therefore other keys.
    sec::SessionContext other = ctx;
    other.purpose = sec::Purpose::End;
    Sha256Digest h2{};
    LM_CHECK_OK(sec::context_hash(other, h2));
    LM_CHECK(h2 != expect);
    other = ctx;
    other.membership_r = MembershipGen{2};
    LM_CHECK_OK(sec::context_hash(other, h2));
    LM_CHECK(h2 != expect);
}

LM_TEST("S04 link replay: duplicate is flagged and never re-applied, tampered and too-old are refused") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    link::SealedFrame first;
    LM_CHECK_OK(n.send(1, 0, payload_of(1), &first));
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[0].fresh(), 1u);
    n.inject(1, 0, first); // duplicate of an accepted frame
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[0].fresh(), 1u);
    LM_CHECK_EQ(n.lnk(0).stats().rx_replay_dup, 1u);
    LM_CHECK_EQ(n.sinks[0].got.size(), 2u); // delivered flagged as duplicate for the re-ACK
    LM_CHECK(n.sinks[0].dup.back());
    // Same counter, different ciphertext: the tag does not verify.
    link::SealedFrame bad = first;
    bad.bytes[wire::k_link_header_bytes + 2] ^= 0x40;
    n.inject(1, 0, bad);
    n.run_ms(50);
    LM_CHECK_EQ(n.lnk(0).stats().rx_auth_fail, 1u);
    // The window survives the forgery: the next genuine frame is accepted.
    LM_CHECK_OK(n.send(1, 0, payload_of(2)));
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[0].fresh(), 2u);
    // 70 more frames push `first` out of the 64-packet window.
    for (int i = 0; i < 70; ++i) {
        LM_CHECK_OK(n.send(1, 0, payload_of(static_cast<uint8_t>(i))));
        n.run_ms(20);
    }
    LM_CHECK_EQ(n.sinks[0].fresh(), 72u);
    n.inject(1, 0, first);
    n.run_ms(50);
    LM_CHECK_EQ(n.lnk(0).stats().rx_replay_old, 1u);
    LM_CHECK_EQ(n.sinks[0].fresh(), 72u);
}

// SEC-D11 (docs/06 §6): a fresh authentic frame enters the replay window only after its minimum checks
// (DATA: a routed body that names this node as the next hop of this sender). A malformed frame with a high
// counter must not push earlier, reordered genuine frames out of the 64-frame window.
LM_TEST("S04 SEC-11 a malformed authentic high-counter DATA frame does not move the replay window") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    // A genuine HOP_ACK sealed first (counter c) and held back: it arrives last (reordered).
    std::array<uint8_t, 16> ack{};
    wire::HopAck a;
    a.acked_link_counter = 7;
    std::size_t alen = 0;
    LM_CHECK_OK(wire::encode_hop_ack(a, MutByteView{ack}, alen));
    link::SealedFrame held;
    LM_CHECK_OK(n.lnk(1).seal(n.id(0), wire::FrameKind::HopAck, ByteView{ack.data(), alen}, held, n.now(1)));
    // 70 counters later the same authenticated peer sends a DATA frame whose routed body does not parse.
    link::SealedFrame junk;
    const Bytes garbage(100, 0xFF); // long enough for the frame decoder, not a routed body
    for (int i = 0; i < 70; ++i) {
        LM_CHECK_OK(n.lnk(1).seal(n.id(0), wire::FrameKind::Data, ByteView{garbage.data(), garbage.size()}, junk,
                                  n.now(1)));
    }
    n.inject(1, 0, junk);
    n.run_ms(20);
    n.inject(1, 0, held);
    n.run_ms(20);
    LM_CHECK_EQ(n.lnk(0).stats().rx_replay_old, 0u); // the held frame is still inside the window
    bool delivered = false;
    for (std::size_t i = 0; i < n.sinks[0].got.size(); ++i) {
        delivered = delivered || (!n.sinks[0].dup[i] && n.sinks[0].got[i] == Bytes(ack.begin(), ack.begin() + alen));
    }
    LM_CHECK(delivered);
    // The junk frame never entered the window: the same bytes again are not an authentic "duplicate".
    n.inject(1, 0, junk);
    n.run_ms(20);
    LM_CHECK_EQ(n.lnk(0).stats().rx_replay_dup, 0u);
}

LM_TEST("S5 glare: both sides connect at once, one exchange wins, one session each") {
    Net n(2);
    LM_CHECK_OK(n.connect(0, 1));
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(4000);
    LM_CHECK(n.paired(0, 1));
    LM_CHECK_EQ(n.lnk(0).neighbors().count(), 1u);
    LM_CHECK_EQ(n.lnk(1).neighbors().count(), 1u);
    // Two exchanges were started, one survived on both sides, nobody failed.
    LM_CHECK_EQ(n.lnk(0).stats().hs_started + n.lnk(1).stats().hs_started, 2u);
    LM_CHECK_EQ(n.lnk(0).stats().hs_completed, 1u);
    LM_CHECK_EQ(n.lnk(1).stats().hs_completed, 1u);
    LM_CHECK_EQ(n.lnk(0).stats().hs_failed + n.lnk(1).stats().hs_failed, 0u);
    LM_CHECK_OK(n.send(0, 1, payload_of(5)));
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[1].fresh(), 1u);
}

LM_TEST("S08 sim: two initiators at one responder share the single handshake slot") {
    Net n(3);
    LM_CHECK_OK(n.connect(1, 0));
    LM_CHECK_OK(n.connect(2, 0));
    n.run_ms(8000);
    LM_CHECK(n.paired(0, 1));
    LM_CHECK(n.paired(0, 2));
    LM_CHECK(n.lnk(0).stats().hs_busy_drop >= 1u || n.lnk(0).stats().hs_completed == 2u);
    LM_CHECK_EQ(n.lnk(0).stats().hs_completed, 2u);
}

namespace {

// The CredI fragments a peer with these credentials would send (replayable: credentials are public).
std::vector<Bytes> cred_i_frames(const fleet::NodeKit &kit, const DomainId &domain) {
    Bytes bundle(member::k_max_bundle);
    std::size_t blen = 0;
    LM_CHECK_OK(member::bundle_encode(ByteView{kit.kit.device_cose.data(), kit.kit.device_cose.size()},
                                      ByteView{kit.member_cose.data(), kit.member_cose.size()},
                                      MutByteView{bundle.data(), bundle.size()}, blen));
    std::array<uint8_t, 16> xid{};
    xid.fill(0x77);
    std::vector<Bytes> frames;
    for (std::size_t off = 0; off < blen; off += wire::k_bootstrap_max_body) {
        const std::size_t n = std::min<std::size_t>(wire::k_bootstrap_max_body, blen - off);
        std::array<uint8_t, 200> carrier{};
        std::size_t clen = 0;
        wire::BootstrapCarrier c;
        c.exchange_id = xid;
        c.object_kind = 1; // CredI
        c.total = static_cast<uint16_t>(blen);
        c.offset = static_cast<uint16_t>(off);
        c.body = ByteView{bundle.data() + off, n};
        LM_CHECK_OK(wire::encode_bootstrap(c, MutByteView{carrier}, clen));
        wire::LinkHeader h;
        h.kind = wire::FrameKind::Edhoc;
        h.domain_hint = link::domain_hint_of(domain);
        h.body_length = static_cast<uint16_t>(clen);
        h.encrypted = false;
        Bytes f(wire::k_link_header_bytes + clen);
        LM_CHECK_OK(wire::encode_link_header(h, MutByteView{f.data(), wire::k_link_header_bytes}));
        std::memcpy(f.data() + wire::k_link_header_bytes, carrier.data(), clen);
        frames.push_back(f);
    }
    return frames;
}

} // namespace

LM_TEST("S08 sim: a replayed CredI holds the single slot for 4 s at most and costs no rate gate") {
    Net n(3);
    // An attacker replays node 1's public credentials with node 1's source MAC; it cannot go on.
    const std::vector<Bytes> frames = cred_i_frames(n.kits[1], n.net.domain);
    LM_CHECK(frames.size() >= 4); // the bundle needs several 160-byte fragments
    for (const Bytes &f : frames) {
        n.world.inject(n.mac(1), 2, n.mac(0), ByteView{f.data(), f.size()});
        n.run_ms(30);
    }
    LM_CHECK(n.lnk(0).exchange().busy()); // credentials verified, waiting for a message_1 that never comes
    n.run_s(1);
    LM_CHECK(n.lnk(0).exchange().busy());
    // While it holds the slot a real initiator is dropped, never served half-way.
    LM_CHECK_OK(n.connect(2, 0));
    n.run_ms(2500);
    LM_CHECK(n.lnk(0).stats().hs_busy_drop >= 1u);
    n.run_s(2); // 4 s after the replay the slot is free again
    LM_CHECK(!n.lnk(0).exchange().busy());
    LM_CHECK(n.lnk(0).exchange().last_failure() == Status::Expired);
    LM_CHECK_EQ(n.eng(0).peers().transient_count(), 0u);
    LM_CHECK_EQ(n.lnk(0).neighbors().count(), 0u);
    n.run_s(31); // node 2's own 30 s gate after its failed attempt; node 0 never touched its gate
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(3000);
    LM_CHECK(n.paired(0, 1));
}

LM_TEST("S08 sim: a second full handshake with the same peer within 30 s is refused at message_1") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    n.reboot(1); // node 1 lost its keys and (RAM) rate gate and tries again at once
    n.run_ms(20);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(6000);
    LM_CHECK(n.lnk(0).stats().hs_rate_limited >= 1u);
    LM_CHECK(!n.session(1, 0));
    LM_CHECK_EQ(n.lnk(1).stats().hs_failed, 1u);
    n.run_s(31);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(3000);
    LM_CHECK(n.paired(0, 1));
}

LM_TEST("S07 wire: credentials of a rogue issuer are refused, no session, no fallback") {
    // S03 sim: a device with the same label (serial) but a key the real fleet never issued.
    Net n(2, 11, false);
    fleet::Network rogue(99, "rogue");
    const fleet::NodeKit fake = rogue.make_node(1, 2); // same index => same serial "node-1"
    LM_CHECK(fake.kit.serial == n.kits[1].kit.serial);
    LM_CHECK(fake.kit.id != n.kits[1].kit.id);
    LM_CHECK_OK(fleet::provision(n.node(0).store, n.net, n.kits[0]));
    LM_CHECK_OK(fleet::provision(n.node(1).store, rogue, fake));
    n.boot(0);
    n.boot(1);
    n.run_ms(20);
    LM_CHECK(n.eng(1).identity().is_member()); // consistent under its own (rogue) anchor
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(6000);
    LM_CHECK_EQ(n.lnk(0).neighbors().count(), 0u);
    LM_CHECK_EQ(n.lnk(1).neighbors().count(), 0u);
    // The domain hint of the rogue domain differs, so the real node drops it before any crypto.
    LM_CHECK(n.lnk(0).stats().rx_wrong_domain >= 1u);
    LM_CHECK_EQ(n.lnk(0).stats().hs_completed, 0u);
}

LM_TEST("S07 wire: valid fleet, forged member credential (not root signed) is refused") {
    // Same fleet and domain, but the MemberCredential is signed by the device's own key.
    Net n(2, 11, false);
    fleet::NodeKit forged = n.kits[1];
    fleet::Kit impostor_root = forged.kit; // a "root" that the delegation does not name
    forged.member_cose = fleet::issue_member(impostor_root, n.net.domain, forged.kit, fleet::MemberSpec{});
    LM_CHECK_OK(fleet::provision(n.node(0).store, n.net, n.kits[0]));
    // The device itself refuses to load its own bad credential (fail closed).
    LM_CHECK_OK(fleet::provision(n.node(1).store, n.net, forged));
    n.boot(0);
    n.boot(1);
    n.run_ms(20);
    LM_CHECK(n.eng(1).identity().state() == member::LocalIdentity::State::Failed);
    LM_CHECK(!n.eng(1).identity().is_member());
    LM_CHECK_EQ(n.connect(1, 0) == Status::AuthPending, true);
}

LM_TEST("S07 low generation: a credential below the revocation floor is refused by the peer") {
    Net n(2, 11, false);
    member::Floors floors;
    LM_CHECK_OK(floors.raise(n.id(1), 1, 2)); // membership floor 2 > the credential's 1
    LM_CHECK_OK(fleet::provision(n.node(0).store, n.net, n.kits[0], true, &floors));
    LM_CHECK_OK(fleet::provision(n.node(1).store, n.net, n.kits[1]));
    n.boot(0);
    n.boot(1);
    n.run_ms(20);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(6000);
    LM_CHECK(!n.session(0, 1) && !n.session(1, 0));
    LM_CHECK(n.lnk(0).stats().cred_rejected >= 1u);
    // The device with a revoked credential also refuses to become a member of its own accord.
    LM_CHECK_OK(fleet::provision(n.node(1).store, n.net, n.kits[1], true, &floors));
    n.node(1).power_cut();
    n.boot(1);
    n.run_ms(20);
    LM_CHECK(n.eng(1).identity().state() == member::LocalIdentity::State::Ready);
    LM_CHECK(!n.eng(1).identity().is_member());
    LM_CHECK(n.eng(1).identity().member_status() == Status::Revoked);
}

// S18-D2: a link whose peer lease is provably over exists only to get that peer renewed: restricted like an
// unprovable lease (no application DATA) and ended after LinkPolicy::renew_window. An end session is refused.
LM_TEST("S07 wire S18: an expired lease gets a restricted renewal-only link, a provable one a full link") {
    Net n(3);
    RootTimeBound t;
    t.valid = true;
    t.term = RootTerm{1};
    t.earliest_ms = t.latest_ms = 0xFFFFFFFFFFFFULL; // past the credentials' lease
    n.eng(2).set_root_time(t, n.now(2)); // the node's estimate (the link layer reads it through delivery)
    LM_CHECK_OK(n.connect(1, 2));
    n.run_ms(6000);
    LM_CHECK(n.paired(2, 1));
    LM_CHECK(n.nb(2, 1)->renew_only && n.nb(2, 1)->lease_uncertain);
    LM_CHECK_EQ(n.lnk(2).stats().renew_only, 1u);
    n.run_s(115);
    LM_CHECK(!n.session(2, 1)); // the renewal window (120 s from the handshake) is over
    t.earliest_ms = t.latest_ms = 1000; // provably before the lease
    n.eng(2).set_root_time(t, n.now(2));
    LM_CHECK_OK(n.connect(2, 1)); // (node 1 still holds its side: it never knew the time)
    n.run_ms(3000);
    LM_CHECK(n.paired(2, 1));
    LM_CHECK(!n.nb(2, 1)->renew_only && !n.nb(2, 1)->lease_uncertain);
}

// ---- SEC-D3: a session is authorised only while its peer's credential lease is ----
namespace {

RootTimeBound root_at(uint64_t ms) {
    RootTimeBound t;
    t.valid = true;
    t.term = RootTerm{1};
    t.earliest_ms = t.latest_ms = ms;
    return t;
}

// Node 1's credential expires at root time `lease_ms`; the root (node 0) lists it as usual. The lease is judged by
// node 2, an ordinary member (the root admits by its ledger, S18-D1).
void short_lease(Net &n, uint64_t lease_ms) {
    fleet::MemberSpec s;
    s.address = 2;
    s.role = 1;
    s.lease_expires_root_ms = lease_ms;
    n.kits[1] = n.net.make_node(1, 2, 1, &s);
    for (uint16_t i = 0; i < 3; ++i) {
        LM_CHECK_OK(fleet::provision(n.node(i).store, n.net, n.kits[i]));
    }
    for (uint16_t i = 0; i < 3; ++i) {
        n.boot(i);
    }
    n.run_ms(20);
}

// A routed application DATA body from address `origin` to the neighbour at `final` (one hop), end record with
// no payload: what the link layer judges before any key of the end session is involved.
Bytes app_data(uint16_t origin, uint16_t final, uint16_t app_port) {
    wire::RouteHeader h;
    h.origin = origin;
    h.final = final;
    h.path_len = 1;
    h.next_index = 0;
    h.budget = 1;
    h.root_term = 1;
    h.path[0] = final;
    Bytes out(wire::k_route_header_bytes + 2 + wire::k_end_header_bytes + wire::k_tag_bytes);
    std::size_t rlen = 0;
    LM_CHECK_OK(wire::encode_route(h, MutByteView{out.data(), out.size()}, rlen));
    wire::EndHeader eh;
    eh.end_sid = 7;
    eh.end_counter = 1;
    eh.app_port = app_port;
    eh.record_kind = app_port == 0 ? wire::RecordKind::Control : wire::RecordKind::Data;
    LM_CHECK_OK(wire::encode_end_header(eh, MutByteView{out.data() + rlen, wire::k_end_header_bytes}));
    out.resize(rlen + wire::k_end_header_bytes + wire::k_tag_bytes);
    return out;
}

} // namespace

LM_TEST("SEC-3 a session admitted while root time was unknown ends once the time proves the peer's lease over") {
    Net n(3, 11, false);
    short_lease(n, 5'000'000);
    LM_CHECK_OK(n.connect(1, 2));
    n.run_ms(3000);
    LM_CHECK(n.paired(2, 1)); // nobody could tell the lease: admitted, restricted
    n.eng(2).set_root_time(root_at(6'000'000), n.now(2));
    n.world.node(2).notify();
    n.run_ms(10);
    LM_CHECK(!n.session(2, 1)); // the lease is provably over: the session is gone at once
    LM_CHECK(n.lnk(2).stats().sessions_lease_expired >= 1u);
}

LM_TEST("SEC-3 a session admitted with a provable lease ends with the lease, not with the key lifetime") {
    Net n(3, 12, false);
    short_lease(n, 5'000'000);
    n.eng(2).set_root_time(root_at(4'990'000), n.now(2)); // 10 s of lease left
    LM_CHECK_OK(n.connect(1, 2));
    n.run_ms(3000);
    LM_CHECK(n.paired(2, 1));
    n.run_ms(9000);
    LM_CHECK(!n.session(2, 1));
}

// S18-D1: the root's own sessions follow its ledger (SEC-D2), not the peer's lease: an expired lease neither restricts
// nor ends them; a ledger change (leave, revocation) does.
LM_TEST("SEC-3 S18 the root's sessions are admitted by its ledger, not capped by the peer's lease") {
    Net n(3, 14, false);
    short_lease(n, 5'000'000);
    n.eng(0).set_root_time(root_at(6'000'000), n.now(0)); // node 1's lease is provably over at the root
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(3000);
    LM_CHECK(n.paired(0, 1));
    LM_CHECK(!n.nb(0, 1)->lease_uncertain && !n.nb(0, 1)->renew_only);
    n.eng(0).set_root_time(root_at(6'100'000), n.now(0));
    n.run_ms(10);
    LM_CHECK(n.session(0, 1));
    LM_CHECK_EQ(n.lnk(0).stats().sessions_lease_expired, 0u);
}

LM_TEST("SEC-3 a time-uncertain session carries no application DATA either way; SDK control passes; time lifts it") {
    Net n(3, 13);
    LM_CHECK_OK(n.connect(1, 2));
    n.run_ms(3000);
    LM_CHECK(n.paired(2, 1));
    n.eng(1).set_root_time(root_at(1'000'000), n.now(1)); // node 1 can tell node 2's lease, node 2 cannot tell its
    const Bytes app = app_data(2, 3, 100);
    const Bytes ctl = app_data(2, 3, 0);
    link::SealedFrame f;
    // Node 2 sends nothing of the application to a peer whose authorisation it cannot prove.
    LM_CHECK(n.lnk(2).seal(n.id(1), wire::FrameKind::Data, ByteView{app_data(3, 2, 100).data(), app.size()}, f,
                           n.now(2)) == Status::TimeUncertain);
    // What node 1 sends: application DATA arrives flagged (the engine answers BUSY), SDK control plainly.
    LM_CHECK_OK(n.lnk(1).seal(n.id(2), wire::FrameKind::Data, ByteView{app.data(), app.size()}, f, n.now(1)));
    n.inject(1, 2, f);
    LM_CHECK_OK(n.lnk(1).seal(n.id(2), wire::FrameKind::Data, ByteView{ctl.data(), ctl.size()}, f, n.now(1)));
    n.inject(1, 2, f);
    n.run_ms(20);
    LM_CHECK_EQ(n.sinks[2].got.size(), 2u);
    if (n.sinks[2].got.size() == 2) {
        LM_CHECK(n.sinks[2].restricted[0] && !n.sinks[2].restricted[1]);
    }
    // Once node 2 knows the time and the lease holds, the restriction is gone.
    n.eng(2).set_root_time(root_at(1'000'000), n.now(2));
    LM_CHECK_OK(n.lnk(2).seal(n.id(1), wire::FrameKind::Data, ByteView{app_data(3, 2, 100).data(), app.size()}, f,
                              n.now(2)));
    LM_CHECK_OK(n.lnk(1).seal(n.id(2), wire::FrameKind::Data, ByteView{app.data(), app.size()}, f, n.now(1)));
    n.inject(1, 2, f);
    n.run_ms(20);
    LM_CHECK(n.sinks[2].got.size() == 3u && !n.sinks[2].restricted.back());
}

// SEC-D2: the root's ledger decides every Link session, so a root whose ledger is not loaded can decide none. That is
// this node's own state, not the peer's fault: no handshake is started or answered (BUSY), nothing counts as a
// rejected credential or a failed exchange, and the same peer links once the ledger is there.
LM_TEST("SEC-2c a root whose ledger is not loaded starts and answers no link handshake: local BUSY, no rejection") {
    Net n(2, 14);
    member::LocalIdentity &id0 = n.eng(0).identity();
    // Another owner holds the identity's record memory when the ledger loads (at boot: the power and channel
    // records): the load waits for its retry while the handshake slot is free.
    LM_CHECK(id0.lend_record() != nullptr);
    n.eng(0).ledger().on_identity_ready(n.now(0));
    n.node(0).notify();
    LM_CHECK(!n.eng(0).ledger().ready() && !n.lnk(0).exchange().busy());
    LM_CHECK(n.connect(0, 1) == Status::Busy);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(40);
    const link::LinkStats &s0 = n.lnk(0).stats();
    LM_CHECK(s0.hs_busy_drop >= 1u);
    LM_CHECK_EQ(s0.hs_started + s0.hs_failed + s0.cred_rejected, 0u);
    id0.return_record();
    n.run_ms(4000); // the ledger loads at its retry; the peer's next CredI is answered
    LM_CHECK(n.eng(0).ledger().ready());
    LM_CHECK(n.paired(0, 1));
    LM_CHECK_EQ(s0.hs_failed + s0.cred_rejected + n.lnk(1).stats().cred_rejected, 0u);
}

LM_TEST("S5 identity: unprovisioned is not failed, a damaged record is not unprovisioned") {
    Net n(3, 11, false);
    LM_CHECK_OK(fleet::provision(n.node(0).store, n.net, n.kits[0]));
    // node 1 stays empty; node 2 has its identity slots overwritten with garbage.
    LM_CHECK_OK(fleet::provision(n.node(2).store, n.net, n.kits[2]));
    const Bytes junk(80, 0x5A);
    LM_CHECK_OK(n.node(2).store.slot_write(store::rec::identity, 0, ByteView{junk.data(), junk.size()}));
    LM_CHECK_OK(n.node(2).store.slot_write(store::rec::identity, 1, ByteView{junk.data(), junk.size()}));
    for (uint16_t i = 0; i < 3; ++i) {
        n.boot(i);
    }
    n.run_ms(20);
    LM_CHECK(n.eng(0).identity().state() == member::LocalIdentity::State::Ready);
    LM_CHECK(n.eng(1).identity().state() == member::LocalIdentity::State::Unprovisioned);
    LM_CHECK(n.eng(2).identity().state() == member::LocalIdentity::State::Failed);
    LM_CHECK(n.eng(2).identity().load_status() != Status::Ok);
    LM_CHECK_EQ(n.connect(1, 0) == Status::AuthPending, true);
    // Frames from a non-member are ignored: the node answers nothing.
    LM_CHECK_OK(n.connect(0, 1));
    n.run_ms(4000);
    LM_CHECK(n.lnk(1).stats().rx_frames >= 1u && n.lnk(1).stats().rx_no_identity >= 1u);
    LM_CHECK_EQ(n.lnk(1).neighbors().count(), 0u);
}

LM_TEST("S05 cold boot: old SID and old ciphertext are refused, fresh EDHOC gives new keys") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    link::SealedFrame f_to0;
    link::SealedFrame f_to1;
    LM_CHECK_OK(n.send(1, 0, payload_of(1), &f_to0));
    n.run_ms(50);
    LM_CHECK_OK(n.send(0, 1, payload_of(2), &f_to1));
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[0].fresh(), 1u);
    LM_CHECK_EQ(n.sinks[1].fresh(), 1u);
    const uint32_t old_sid_at_0 = n.nb(0, 1)->cur.rx_sid;
    const uint32_t old_sid_at_1 = n.nb(1, 0)->cur.rx_sid;

    n.reboot(0); // node 0 cold boots: keys and windows are gone, membership comes from Flash
    n.run_ms(20);
    LM_CHECK(n.eng(0).identity().is_member());
    LM_CHECK_EQ(n.lnk(0).neighbors().count(), 0u);
    n.inject(1, 0, f_to0); // old ciphertext, old SID
    n.run_ms(50);
    LM_CHECK_EQ(n.lnk(0).stats().rx_unknown_sid, 1u);
    LM_CHECK_EQ(n.sinks[0].got.size(), 1u); // still only the pre-reboot delivery
    LM_CHECK_EQ(n.send(0, 1, payload_of(3)) == Status::AuthPending, true); // no session: no send

    n.run_s(31); // the per-peer full-handshake gate at node 1
    LM_CHECK_OK(n.connect(0, 1));
    n.run_ms(3000);
    LM_CHECK(n.paired(0, 1));
    LM_CHECK(n.nb(0, 1)->cur.rx_sid != old_sid_at_0);
    LM_CHECK(n.nb(1, 0)->cur.rx_sid != old_sid_at_1);
    // The old session survives at node 1 only as a short receive-only grace (no overlap forever).
    LM_CHECK(n.lnk(1).neighbors().has_grace(n.nb(1, 0)->mac));
    n.inject(0, 1, f_to1); // node 0's pre-reboot frame: authentic duplicate inside the grace
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[1].fresh(), 1u); // never applied twice
    LM_CHECK_EQ(n.lnk(1).stats().rx_replay_dup, 1u);
    // New traffic uses the new keys and flows.
    LM_CHECK_OK(n.send(1, 0, payload_of(7)));
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[0].fresh(), 2u);
    n.run_s(11); // grace over
    LM_CHECK(!n.lnk(1).neighbors().has_grace(n.nb(1, 0)->mac));
    const uint64_t before = n.lnk(1).stats().rx_unknown_sid;
    n.inject(0, 1, f_to1);
    n.run_ms(50);
    LM_CHECK_EQ(n.lnk(1).stats().rx_unknown_sid, before + 1);
    LM_CHECK_EQ(n.sinks[1].fresh(), 1u);
}

LM_TEST("LP13 sim: only the restarted parent's session is re-established, no other exchange") {
    Net n(3);
    LM_CHECK_OK(n.connect(2, 1));
    n.run_ms(3000);
    LM_CHECK_OK(n.connect(2, 0));
    n.run_ms(3000);
    LM_CHECK(n.paired(2, 1));
    LM_CHECK(n.paired(2, 0));
    const uint32_t sid_other = n.nb(2, 0)->cur.rx_sid;
    const Sha256Digest ctx_other = n.nb(2, 0)->cur.ctx_hash;
    const uint64_t started_at_0 = n.lnk(0).stats().hs_started;
    n.reboot(1); // parent restarts; leaf 2 keeps its RAM
    n.run_ms(20);
    n.run_s(31);
    LM_CHECK_OK(n.connect(1, 2));
    n.run_ms(3000);
    LM_CHECK(n.paired(2, 1));
    LM_CHECK(n.nb(2, 0)->cur.rx_sid == sid_other && n.nb(2, 0)->cur.ctx_hash == ctx_other);
    LM_CHECK_EQ(n.lnk(0).stats().hs_started, started_at_0); // the rest of the network saw nothing
    LM_CHECK(n.eng(1).identity().is_member()); // membership was never re-approved
}

LM_TEST("S05 failure: SESSION_BIND lost, three attempts, no session and no early DATA, then recovery") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    // The responder has its keys and message_4 is in the air; the initiator still needs two jobs
    // before it can send SESSION_BIND, and by then the medium is gone.
    LM_CHECK(n.run_until([&] { return n.lnk(0).exchange().phase() == link::Phase::AwaitBind; }, 5000));
    n.world.set_link(0, 1, LinkParams{false, 0, 0, 1000});
    n.run_ms(6000);
    LM_CHECK(!n.session(0, 1) && !n.session(1, 0)); // the responder never saw a BIND: no session
    LM_CHECK_EQ(n.lnk(1).stats().hs_failed, 1u);
    LM_CHECK(n.lnk(1).exchange().last_failure() == Status::Expired);
    LM_CHECK_EQ(n.lnk(1).stats().hs_retransmits, 2u); // 3 transmissions in total
    LM_CHECK_EQ(n.send(1, 0, payload_of(1)) == Status::AuthPending, true);
    n.world.set_link(0, 1, LinkParams{true, 0, 0, 1000});
    LM_CHECK_EQ(n.connect(1, 0) == Status::RateLimited, true); // < 30 s since the last handshake
    n.run_s(31);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(3000);
    LM_CHECK(n.paired(0, 1));
}

LM_TEST("S5 local shortage is not RF loss: radio BUSY delays the exchange, it does not fail it") {
    Net n(2);
    n.node(1).radio.tx_fault = Status::Busy;
    n.node(1).radio.tx_fault_count = 3;
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(3000);
    LM_CHECK(n.paired(0, 1));
    LM_CHECK(n.eng(1).tx().stats().local_refused >= 3u);
    LM_CHECK_EQ(n.eng(1).tx().stats().rf_failed, 0u);
    LM_CHECK_EQ(n.lnk(1).stats().tx_rf_failed, 0u);
    LM_CHECK(n.lnk(1).stats().tx_local_busy >= 3u);
}

LM_TEST("S5 RF loss: retransmissions of identical bytes complete the exchange, loss is counted as loss") {
    Net n(2, 5);
    n.world.set_link(0, 1, LinkParams{true, 120, 1000, 100});
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(20000);
    LM_CHECK(n.paired(0, 1));
    LM_CHECK(n.lnk(1).stats().hs_retransmits >= 1u);
    LM_CHECK(n.eng(1).tx().stats().rf_failed + n.eng(0).tx().stats().rf_failed >= 1u);
}

LM_TEST("R10 stop while a handshake job is in flight: zombie slot, late completion cannot act") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    LM_CHECK(n.run_until([&] { return n.lnk(1).exchange().phase() == link::Phase::Hs; }, 5000));
    LM_CHECK_EQ(lm_stop(n.node(1).ctx(), 0, nullptr), LM_STATUS_OK);
    LM_CHECK(n.lnk(1).exchange().phase() == link::Phase::Zombie); // memory reserved for the job
    LM_CHECK_EQ(n.lnk(1).neighbors().count(), 0u);
    n.run_ms(500); // the worker finishes and the completion is polled
    LM_CHECK(n.lnk(1).exchange().phase() == link::Phase::Idle);
    LM_CHECK_EQ(lm_start(n.node(1).ctx()), LM_STATUS_OK);
    n.run_ms(20);
    LM_CHECK(n.eng(1).identity().is_member());
    n.run_s(31);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(3000);
    LM_CHECK(n.paired(0, 1));
}

LM_TEST("S10 rotation: lower DeviceId rotates at 50 min, old session receives a bounded grace only") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    const uint16_t lower = n.id(0) < n.id(1) ? 0 : 1;
    const uint16_t higher = lower == 0 ? 1 : 0;
    const uint32_t old_sid = n.nb(lower, higher)->cur.rx_sid;
    // One frame per minute, alternating direction, through the whole rotation point.
    std::size_t sent = 0;
    for (int minute = 0; minute < 56; ++minute) {
        n.run_s(60);
        const uint16_t a = minute % 2 == 0 ? 0 : 1;
        const uint16_t b = a == 0 ? 1 : 0;
        LM_CHECK_OK(n.send(a, b, payload_of(static_cast<uint8_t>(minute))));
        n.run_ms(100);
        ++sent;
    }
    LM_CHECK_EQ(n.sinks[0].fresh() + n.sinks[1].fresh(), sent); // nothing lost across the switch
    LM_CHECK_EQ(n.lnk(lower).stats().rotations_started, 1u);
    LM_CHECK(n.paired(0, 1));
    LM_CHECK(n.nb(lower, higher)->cur.rx_sid != old_sid);
    LM_CHECK(!n.lnk(0).neighbors().has_grace(n.nb(0, 1)->mac) && !n.lnk(1).neighbors().has_grace(n.nb(1, 0)->mac)); // grace is over
    LM_CHECK_EQ(n.lnk(0).stats().sessions_replaced + n.lnk(1).stats().sessions_replaced, 2u);
    LM_CHECK_EQ(n.lnk(0).stats().hs_failed + n.lnk(1).stats().hs_failed, 0u);
}

LM_TEST("S10 rotation with lost exchange keeps the old session until the new one is bound, hard limit 1 h") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    const uint16_t lower = n.id(0) < n.id(1) ? 0 : 1;
    const uint16_t higher = lower == 0 ? 1 : 0;
    const uint32_t old_sid = n.nb(lower, higher)->cur.rx_sid;
    const uint64_t rotate_at_s = 3000;
    n.run_s(rotate_at_s - 2000 / 1000 * 1000 / 1000); // just before the rotation time (born ~ 0.1 s)
    n.world.set_link(0, 1, LinkParams{false, 0, 0, 1000}); // the exchange cannot get through
    n.run_s(8);
    LM_CHECK(n.lnk(lower).stats().hs_failed >= 1u);
    LM_CHECK(n.session(0, 1) && n.session(1, 0)); // old session untouched
    n.world.set_link(0, 1, LinkParams{true, 0, 0, 1000});
    LM_CHECK_OK(n.send(lower, higher, payload_of(1))); // still sealed under the old key
    n.run_ms(100);
    LM_CHECK_EQ(n.sinks[higher].fresh(), 1u);
    LM_CHECK(n.nb(lower, higher)->cur.rx_sid == old_sid);
    n.run_s(90); // the 30 s gate opens, the retry succeeds
    LM_CHECK(n.paired(0, 1));
    LM_CHECK(n.nb(lower, higher)->cur.rx_sid != old_sid);

    // Hard limit: with no way to rotate, the key dies at one hour and nothing overlaps beyond it.
    Net m(2);
    LM_CHECK_OK(m.connect(1, 0));
    m.run_ms(2000);
    LM_CHECK(m.paired(0, 1));
    m.world.set_link(0, 1, LinkParams{false, 0, 0, 1000});
    m.run_s(3650);
    LM_CHECK(!m.session(0, 1) && !m.session(1, 0));
    LM_CHECK_EQ(m.send(0, 1, payload_of(1)) == Status::AuthPending, true);
    LM_CHECK_EQ(m.lnk(0).neighbors().count(), 0u); // the neighbour slot and its peer are released
    LM_CHECK_EQ(m.eng(0).peers().regular_count(), 0u);
}

LM_TEST("S10 rotation by record count: threshold reached, fresh EDHOC, no loss") {
    Net n(2);
    n.lnk(0).policy().rotate_records = 6;
    n.lnk(1).policy().rotate_records = 6;
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    const uint32_t old_sid = n.nb(1, 0)->cur.rx_sid;
    for (int i = 0; i < 8; ++i) {
        LM_CHECK_OK(n.send(1, 0, payload_of(static_cast<uint8_t>(i))));
        n.run_ms(30);
    }
    n.run_s(60); // gate (30 s) then the rotation exchange
    LM_CHECK(n.paired(0, 1));
    LM_CHECK(n.nb(1, 0)->cur.rx_sid != old_sid);
    LM_CHECK(n.lnk(1).stats().rotations_started >= 1u);
    LM_CHECK_EQ(n.sinks[0].fresh(), 8u);
    LM_CHECK_OK(n.send(1, 0, payload_of(99)));
    n.run_ms(50);
    LM_CHECK_EQ(n.sinks[0].fresh(), 9u);
}

LM_TEST("R08 sim: a full neighbour table refuses the next session and evicts nobody") {
    constexpr unsigned k_nodes = 18; // root profile: 16 neighbours
    Net n(k_nodes);
    for (uint16_t i = 1; i < k_nodes; ++i) {
        LM_CHECK_OK(n.connect(i, 0));
        n.run_ms(1500);
    }
    LM_CHECK_EQ(n.lnk(0).neighbors().count(), 16u);
    for (uint16_t i = 1; i <= 16; ++i) {
        LM_CHECK(n.paired(0, i));
    }
    LM_CHECK(!n.session(0, 17));
    LM_CHECK(n.lnk(0).stats().hs_failed >= 1u);
    LM_CHECK(n.eng(0).peers().regular_count() == 16u);
    LM_CHECK(n.eng(0).peers().transient_count() == 0u); // the failed exchange released its peer
}

LM_TEST("ME05 sim: an established idle link costs zero owner wakes") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_s(10); // handshake done, responder linger over
    LM_CHECK(n.paired(0, 1));
    const uint64_t s0 = n.eng(0).stats().steps;
    const uint64_t s1 = n.eng(1).stats().steps;
    n.run_s(1500);
    LM_CHECK_EQ(n.eng(0).stats().steps, s0);
    LM_CHECK_EQ(n.eng(1).stats().steps, s1);
}

LM_TEST("measure: owner stack depth of the per-frame link paths (RX open + dispatch, TX seal)") {
    Net n(2);
    LM_CHECK_OK(n.connect(1, 0));
    n.run_ms(2000);
    LM_CHECK(n.paired(0, 1));
    link::SealedFrame f;
    const Bytes p100 = payload_of(1, 100);
    LM_CHECK_OK(n.lnk(1).seal(n.id(0), wire::FrameKind::Control, ByteView{p100.data(), p100.size()}, f,
                              n.now(1)));
    port::RadioRx rx;
    rx.src = n.mac(1);
    rx.len = static_cast<uint8_t>(f.len);
    std::memcpy(rx.bytes.data(), f.bytes.data(), f.len);
    bool consumed = false;
    link::SealedFrame g;
    Status seal_status = Status::Ok;
    const Bytes big = payload_of(2, 150);
    const std::size_t depth = lmtest::depth_of([&] {
        consumed = n.lnk(0).on_rx(rx, n.now(0));
        seal_status = n.lnk(0).seal(n.id(1), wire::FrameKind::Control, ByteView{big.data(), big.size()}, g,
                                    n.now(0));
    });
    LM_CHECK(consumed);
    LM_CHECK_OK(seal_status);
    LM_CHECK_EQ(n.sinks[0].fresh(), 1u);
    std::printf("  [measure] owner stack depth, RX open+dispatch then TX seal: %zu B (entry depth %zu B)\n",
                depth, lmtest::entry_depth());
#if LM_STACK_PROBE_EXACT
    LM_CHECK(depth < 3500); // IdfOwner::k_stack_bytes is 4096; the step()/event frames come on top
#endif
}

LM_TEST("measure: worker stack depth of one EDHOC handshake") {
    Net n(2, 11, false);
    (void)sec::crypto_init();
    sec::KeyHandle ka;
    sec::KeyHandle kb;
    LM_CHECK_OK(sec::import_signing_key(ByteView{n.kits[0].kit.scalar}, ka));
    LM_CHECK_OK(sec::import_signing_key(ByteView{n.kits[1].kit.scalar}, kb));
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs_a{};
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs_b{};
    std::size_t la = 0;
    std::size_t lb = 0;
    const auto &da = n.kits[0].kit.dc;
    const auto &db = n.kits[1].kit.dc;
    LM_CHECK_OK(sec::ccs_encode(ByteView{da.serial.data(), da.serial_len}, da.key, MutByteView{ccs_a}, la));
    LM_CHECK_OK(sec::ccs_encode(ByteView{db.serial.data(), db.serial_len}, db.key, MutByteView{ccs_b}, lb));
    auto *I = new sec::HandshakeSlot();
    auto *R = new sec::HandshakeSlot();
    sim::SimStore store{sim::StoreGeometry{}};
    port::JobEnv env{store};
    Status st = Status::Ok;
    auto step = [&](sec::HandshakeSlot &s, sec::HsStep h, ByteView in) {
        if (st != Status::Ok) {
            return;
        }
        st = s.prepare(h, in);
        if (st == Status::Ok) {
            st = s.complete(sec::HandshakeSlot::run_job(env, &s));
        }
    };
    sec::SessionContext ctx;
    ctx.initiator = n.kits[0].kit.id;
    ctx.responder = n.kits[1].kit.id;
    const ByteView pb[1] = {ByteView{ccs_b.data(), lb}};
    const ByteView pa[1] = {ByteView{ccs_a.data(), la}};
    LM_CHECK_OK(I->begin(sec::HsRole::Initiator, ka, ByteView{ccs_a.data(), la}, pb, 1));
    LM_CHECK_OK(R->begin(sec::HsRole::Responder, kb, ByteView{ccs_b.data(), lb}, pa, 1));
    const std::size_t depth = lmtest::depth_of([&] {
        using S = sec::HsStep;
        step(*I, S::M1Compose, ByteView{});
        step(*R, S::M1Process, I->output());
        step(*R, S::M2Compose, ByteView{});
        step(*I, S::M2Process, R->output());
        step(*I, S::M3Compose, ByteView{});
        step(*R, S::M3Process, I->output());
        step(*R, S::M4Compose, ByteView{});
        step(*I, S::M4Process, R->output());
        if (st == Status::Ok) {
            st = I->set_context(ctx);
        }
        if (st == Status::Ok) {
            st = R->set_context(ctx);
        }
        step(*I, S::Export, ByteView{});
        step(*R, S::Export, ByteView{});
    });
    LM_CHECK(st == Status::Ok);
    std::printf("  [measure] EDHOC worker stack: deepest job body %zu B (thread entry depth %zu B)\n", depth,
                lmtest::entry_depth());
    sec::destroy_key(ka);
    sec::destroy_key(kb);
#if LM_STACK_PROBE_EXACT
    // SEC-D15: the worker stack of this optimisation level keeps at least twice the deepest job body.
    LM_CHECK(2 * depth <= port::k_worker_stack_bytes);
#endif
    delete I;
    delete R;
}

LM_TEST("measure: sizeof of the new owner state") {
    std::printf("  [measure] sizeof(Neighbor)=%zu x %zu, LinkLayer=%zu, Exchange=%zu, HandshakeSlot=%zu,\n"
                "            LocalIdentity=%zu, Engine=%zu, lm_context=%zu, SessionKeys=%zu, SealedFrame=%zu\n",
                sizeof(link::Neighbor), link::k_max_neighbors, sizeof(link::LinkLayer),
                sizeof(link::Exchange), sizeof(sec::HandshakeSlot), sizeof(member::LocalIdentity),
                sizeof(Engine), sizeof(lm_context), sizeof(link::SessionKeys), sizeof(link::SealedFrame));
}

LM_TEST_MAIN()
