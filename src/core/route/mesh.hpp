// The mesh module of the owner (docs/04 §3, §5, §6; IMPLEMENTATION.md S11): how a node finds a
// parent, is admitted to the root's tree, keeps its root path alive, resolves paths to other nodes
// and repairs when its parent disappears. One state machine per node; the root runs the same object
// in state Root (it advertises itself and answers) and hands the tree work to root::Routes.
//
//   Listen  800 ms without transmitting (a peer that already talks makes a hello unnecessary)
//   Search  no parent: solicit, collect beacons, pick the best candidate (lowest depth, measured
//           quality once known)
//   Attach  one candidate is being tried: link session -> PROBE -> end session with the root -> REGISTER
//           -> LEASE -> READY -> LEASE. The root approves one request at a time against its tree, so
//           concurrent choices can never close a cycle; the old path serves until READY applied.
//   Ready   approved path with a lease (60 s renewal, 180 s validity); spares stay linked and probed
//
// What is a failure: only a targeted RF failure (3 missing HOP_ACKs to the parent, MacFailed probes) or
// silence of three hello intervals. BUSY, a full TX pool and planned sleep never count. Nothing here polls:
// every action is a deadline or an event. Bounded: 3 candidates, 2 query slots, one attach at a time.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/delivery/delivery.hpp"
#include "core/link/link_layer.hpp"
#include "core/member/discovery.hpp"
#include "core/radio/tx_manager.hpp"
#include "core/route/mesh_wire.hpp"
#include "core/route/score.hpp"

namespace lm {
class Engine;
}

namespace lm::route {

inline constexpr std::size_t k_cands = 3;   // parent + 2 spares (docs/04 §2)
inline constexpr std::size_t k_query_slots = 2;
inline constexpr uint32_t k_tag_mesh = 0x4D530000; // "MS": beacons and probes (low bits: kind<<8 | candidate)

class Mesh {
  public:
    enum class State : uint8_t { Off, Listen, Search, Attach, Ready, Root };

    explicit Mesh(Engine &engine);
    Mesh(const Mesh &) = delete;
    Mesh &operator=(const Mesh &) = delete;

    // ---- Engine wiring ----
    void install(); // registers the delivery hooks (constructor time)
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void stop();
    void on_beacon(const MacAddr &src, ByteView body, MonoTime now);
    void on_route_frame(const link::RxInfo &info, ByteView plain, MonoTime now);
    void on_link_up(const DeviceId &peer, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    [[nodiscard]] static bool is_mesh_tag(uint32_t tag) { return (tag & 0xFFFF0000U) == k_tag_mesh; }

    // [S16] power: the approved parent with a live link session (the poll goes there), and the wake after a sleep:
    // nothing was heard while asleep, and silence over a sleep is not a dead parent.
    [[nodiscard]] bool parent_link(MacAddr &mac, DeviceId &dev) const;
    [[nodiscard]] bool parent_link_up() const {
        MacAddr m;
        DeviceId d;
        return parent_link(m, d);
    }
    void on_wake(MonoTime now, bool fresh_sessions);
    // The parent did not answer an authenticated poll twice: it most likely lost the session (a restart). Only
    // that session is made again, at once, instead of waiting for silent hello intervals (docs/20 §7 row 4).
    void parent_session_lost(const MacAddr &mac, MonoTime now);
    // ARCH2-D1: the node now follows a newer root term (Engine::on_new_term): register again in it.
    void on_term(MonoTime now);

    // Bench switch (sim nodes of slices that drive links by hand). Product builds never call it.
    void set_enabled(bool on) { enabled_ = on; }

    // ---- services ----
    // May this node relay a joiner's frames (a relay attached to the tree, or the root)?
    [[nodiscard]] bool proxy_capable(MonoTime now) const;
    [[nodiscard]] uint8_t depth() const { return state_ == State::Root ? 0 : (path_n_ > 0 ? path_n_ - 1 : 0); }
    // Route from this node to the root (own path reversed); false while there is none valid.
    [[nodiscard]] bool route_to_root(delivery::PathSpec &out, MonoTime now) const;
    [[nodiscard]] uint32_t expected_revision() const { return expected_rev_; }
    // [S17] channel module: the parent's radio address (survey probes), a hint request on the channel the node
    // is tuned to (recovery scan), and whether a beacon of a possible parent arrived since `t`.
    [[nodiscard]] bool parent_mac(MacAddr &out) const {
        if (parent_ < 0) {
            return false;
        }
        out = cands_[static_cast<std::size_t>(parent_)].mac;
        return true;
    }
    void hello_now(MonoTime now) {
        if (state_ != State::Off && state_ != State::Ready && state_ != State::Root) {
            send_beacon(true, now);
        }
    }
    [[nodiscard]] bool heard_since(MonoTime t) const {
        for (const Cand &c : cands_) {
            if (c.used && c.heard >= t) {
                return true;
            }
        }
        return false;
    }

    // ---- observation (tests, diagnostics) ----
    struct Stats {
        uint64_t beacons_tx = 0, beacons_rx = 0, probes_tx = 0, probes_rx = 0;
        uint64_t registers = 0, leases = 0, readies = 0, queries = 0, answers = 0;
        uint64_t suspects = 0, attach_failed = 0, tx_busy = 0;
        uint64_t last_repair_ms = 0; // suspect -> path approved again
    };
    [[nodiscard]] State state() const { return state_; }
    [[nodiscard]] bool repairing() const { return repairing_; }
    [[nodiscard]] uint8_t attach_step_id() const { return static_cast<uint8_t>(att_.step); } // 0 idle .. 5 confirm
    [[nodiscard]] const Stats &stats() const { return stats_; }
    [[nodiscard]] const member::Discovery &discovery() const { return disc_; }
    [[nodiscard]] ShortAddr parent_addr() const {
        return parent_ >= 0 ? ShortAddr{cands_[static_cast<std::size_t>(parent_)].addr} : ShortAddr{};
    }
    [[nodiscard]] uint8_t path_size() const { return path_n_; }
    [[nodiscard]] const uint16_t *path() const { return path_.data(); }
    [[nodiscard]] PathRevision path_revision() const { return PathRevision{rev_}; }
    [[nodiscard]] MonoTime ready_since() const { return ready_since_; }

  private:
    struct Cand {
        bool used = false;
        MacAddr mac;
        uint16_t addr = 0;
        uint32_t revision = 0; // path_revision the candidate advertised
        uint8_t n = 0;         // its root path entries (root first, itself last)
        std::array<uint16_t, k_max_root_path> path{};
        MonoTime heard{};
        bool unproven = false; // an end session through this link failed: prove the link before relying on it (ARCH2-D2)
        MonoTime avoid_until{};
        MonoTime probe_wait = MonoTime::never();
        std::array<uint8_t, 8> nonce{};
        LinkQuality q;
        Instability inst;
        uint8_t fails = 0;
        uint8_t rf_streak = 0; // consecutive MacFailed samples
        uint8_t probe_miss = 0; // probes in a row that got no reply although the radio acked them
    };
    enum class Step : uint8_t { Idle, Link, Probe, Session, Register, Confirm };
    struct Attach {
        Step step = Step::Idle;
        int cand = -1;
        uint8_t tries = 0;
        uint32_t sequence = 0;
        uint32_t revision = 0; // granted, applied only when READY is answered
        uint8_t n = 0;
        std::array<uint16_t, k_max_root_path> path{};
        MonoTime next_at = MonoTime::never();
        bool switching = false; // a voluntary move: the old path keeps serving
    };
    struct Ask { // one ROUTE_QUERY in flight (or a recent refusal, kept 5 s so a sender does not hammer the root)
        bool used = false;
        uint8_t qid = 0;
        DeviceId dest;
        MonoTime next_at = MonoTime::never();
        uint8_t tries = 0;
    };

    // hooks (static trampolines installed into Delivery)
    static void hook_control(void *ctx, const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now);
    static void hook_session(void *ctx, const DeviceId &peer, Status st, MonoTime now);
    static void hook_tunnel(void *ctx, const delivery::PathSpec &reply, ByteView plain, MonoTime now);
    static void hook_frame_done(void *ctx, const delivery::FrameDone &f, delivery::HopEnd end, MonoTime now);
    static Status hook_route_of(void *ctx, const DeviceId &dest, delivery::PathSpec &out, MonoTime now);
    static void hook_want_route(void *ctx, const DeviceId &dest, MonoTime now);
    static void hook_slot_free(void *ctx, MonoTime now);

    [[nodiscard]] bool is_root() const;
    void sync(MonoTime now);
    void begin(MonoTime now);
    [[nodiscard]] uint16_t jitter(uint16_t modulus);
    [[nodiscard]] RootTerm term() const;
    [[nodiscard]] ShortAddr self_addr() const;
    [[nodiscard]] const DeviceId &root_id() const;
    [[nodiscard]] bool path_valid(MonoTime now) const { return state_ == State::Ready && now < lease_until_; }

    // candidates
    [[nodiscard]] Cand *find_cand(const MacAddr &mac);
    [[nodiscard]] Cand *alloc_cand(int keep);
    [[nodiscard]] int index_of(const Cand *c) const { return static_cast<int>(c - cands_.data()); }
    [[nodiscard]] const link::Neighbor *neighbor_of(const Cand &c) const;
    [[nodiscard]] bool linked(const Cand &c) const;
    [[nodiscard]] int pick_candidate(MonoTime now) const;
    [[nodiscard]] uint32_t score_of(const Cand &c, MonoTime now) const;

    // beacons, probes, trickle
    void send_beacon(bool solicit, MonoTime now);
    void schedule_beacon(MonoTime now, uint16_t max_delay_ms);
    void send_probe(Cand &c, MonoTime now);
    void drop_link(Cand &c);
    void trickle(MonoTime now);
    void trickle_reset(MonoTime now);
    void on_probe(const link::RxInfo &info, const Probe &p, MonoTime now);
    void heard(Cand &c, MonoTime now);
    void alive(Cand &c, MonoTime now);
    void rf_sample(Cand &c, bool ok, MonoTime now);
    void note(Cand &c, bool ok, MonoTime now); // [S17] one RF attempt: link quality + the channel module's window

    // attach / repair
    void search_step(MonoTime now);
    void begin_attach(int ci, bool switching, MonoTime now);
    void attach_step(MonoTime now);
    void attach_fail(MonoTime now, bool soft = false);
    void attach_timer(MonoTime now);
    void send_register(MonoTime now);
    void send_ready(MonoTime now);
    void suspect(MonoTime now);
    void lose_path(MonoTime now);
    void commit(const LeaseRec &l, MonoTime now);
    void on_lease(const LeaseRec &l, MonoTime now);
    void on_answer(const Answer &a, MonoTime now);
    void on_control(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now);
    void on_session(const DeviceId &peer, Status st, MonoTime now);
    void on_frame_done(const delivery::FrameDone &f, delivery::HopEnd end, MonoTime now);
    void on_slot_free(MonoTime now);
    void want_route(const DeviceId &dest, MonoTime now);
    [[nodiscard]] Status route_of(const DeviceId &dest, delivery::PathSpec &out, MonoTime now) const;
    [[nodiscard]] bool route_via(const uint16_t *root_path, uint8_t n, uint32_t revision,
                                 delivery::PathSpec &out) const;
    [[nodiscard]] Status to_root(ByteView body, const delivery::PathSpec &route, MonoTime now);
    void renew(MonoTime now);
    void query_timer(MonoTime now);
    void connect_spare(MonoTime now);
    [[nodiscard]] uint32_t next_sequence();
    [[nodiscard]] uint64_t credential_lease(bool attach) const;

    Engine &engine_;
    State state_ = State::Off;
    bool enabled_ = true;
    member::Discovery disc_;
    Stats stats_;
    std::array<Cand, k_cands> cands_{};
    std::array<Ask, k_query_slots> asks_{};
    Attach att_;
    int parent_ = -1;

    // approved path (root first, self last), valid only in Ready
    std::array<uint16_t, k_max_root_path> path_{};
    uint8_t path_n_ = 0;
    uint32_t rev_ = 0;
    uint32_t expected_rev_ = 0;
    MonoTime lease_until_{};
    bool lease_lapsed_ = true; // no valid lease (yet, or it ran out): the deadline is not armed
    MonoTime ready_since_ = MonoTime::never();
    MonoTime renew_at_ = MonoTime::never();
    MonoTime renew_wait_ = MonoTime::never();
    uint8_t renew_tries_ = 0;

    bool repairing_ = false;
    MonoTime repair_since_{};
    MonoTime parent_since_{};
    MonoTime attempt_at_ = MonoTime::never(); // Search: look at the candidates then
    MonoTime probe_retry_at_ = MonoTime::never();
    MonoTime beacon_at_ = MonoTime::never();  // a beacon is due (answer to a solicit, change, or TX busy)
    bool beacon_solicit_ = false;
    MonoTime trickle_at_ = MonoTime::never();
    Duration trickle_i_ = Duration::from_ms(gen::defaults::routing::hello_min_ms);
    uint8_t trickle_n_ = 0;
    MonoTime spare_at_ = MonoTime::never();
    MonoTime last_solicit_answer_{};
    uint32_t seq_counter_ = 0;
    uint8_t next_qid_ = 1;
};

} // namespace lm::route
