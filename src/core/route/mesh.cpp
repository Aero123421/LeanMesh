#include "core/route/mesh.hpp"

#include <algorithm>

#include "core/engine.hpp"
#include "core/route/forward.hpp"
#include "core/route/stitch.hpp"

namespace lm::route {
namespace {

constexpr Duration k_probe_wait = Duration::from_ms(1500);
constexpr Duration k_probe_fresh = Duration::from_s(20); // a candidate not heard for this long is probed before use
constexpr Duration k_link_wait = Duration::from_s(6);      // a link handshake takes a few seconds at most
constexpr Duration k_attach_hard = Duration::from_s(60);   // one candidate, all steps
constexpr Duration k_session_wait = Duration::from_s(30);  // registry session_binding.timeout_ms
constexpr Duration k_busy_retry = Duration::from_ms(20);   // radio/TX pool busy: local, not a failure
constexpr Duration k_slot_retry = Duration::from_ms(250);
constexpr Duration k_lease_margin = Duration::from_s(2);
constexpr Duration k_hello_max = Duration::from_ms(gen::defaults::routing::hello_max_ms);
constexpr Duration k_silence = Duration::from_ms(gen::defaults::routing::hello_max_ms *
                                                 gen::defaults::routing::idle_liveness_multiplier);
constexpr Duration k_lease_refresh = Duration::from_ms(gen::defaults::routing::lease_refresh_ms);
constexpr Duration k_route_life = Duration::from_s(120); // a stitched route lives less than a lease
constexpr Duration k_negative_life = Duration::from_s(5);
constexpr uint8_t k_rf_failures = static_cast<uint8_t>(gen::defaults::routing::parent_failures);
constexpr uint8_t k_kind_beacon = 1;
constexpr uint8_t k_kind_probe = 2;

} // namespace

Mesh::Mesh(Engine &engine) : engine_(engine) {}

void Mesh::install() {
    delivery::MeshHooks h;
    h.ctx = this;
    h.control = &hook_control;
    h.session = &hook_session;
    h.tunnel = &hook_tunnel;
    h.frame_done = &hook_frame_done;
    h.route_of = &hook_route_of;
    h.want_route = &hook_want_route;
    h.slot_free = &hook_slot_free;
    engine_.delivery().set_mesh(h);
}

void Mesh::hook_control(void *ctx, const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now) {
    static_cast<Mesh *>(ctx)->on_control(peer, reply, body, now);
}
void Mesh::hook_session(void *ctx, const DeviceId &peer, Status st, MonoTime now) {
    static_cast<Mesh *>(ctx)->on_session(peer, st, now);
}
void Mesh::hook_tunnel(void *ctx, const delivery::PathSpec &reply, ByteView plain, MonoTime now) {
    static_cast<Mesh *>(ctx)->engine_.proxy().on_record(reply, plain, now);
}
void Mesh::hook_frame_done(void *ctx, const delivery::FrameDone &f, delivery::HopEnd end, MonoTime now) {
    static_cast<Mesh *>(ctx)->on_frame_done(f, end, now);
}
Status Mesh::hook_route_of(void *ctx, const DeviceId &dest, delivery::PathSpec &out, MonoTime now) {
    return static_cast<Mesh *>(ctx)->route_of(dest, out, now);
}
void Mesh::hook_want_route(void *ctx, const DeviceId &dest, MonoTime now) {
    static_cast<Mesh *>(ctx)->want_route(dest, now);
}
void Mesh::hook_slot_free(void *ctx, MonoTime now) { static_cast<Mesh *>(ctx)->on_slot_free(now); }

// ---- small helpers ----
bool Mesh::is_root() const { return k_root_capable && engine_.config().role == Role::Root; }
RootTerm Mesh::term() const { return engine_.identity().member().root_term; }
ShortAddr Mesh::self_addr() const { return engine_.identity().member().address; }
const DeviceId &Mesh::root_id() const { return engine_.identity().delegation().root; }

uint16_t Mesh::jitter(uint16_t modulus) {
    std::array<uint8_t, 2> r{};
    engine_.random(MutByteView{r});
    return modulus == 0 ? 0 : static_cast<uint16_t>((uint32_t{r[0]} << 8U | r[1]) % modulus);
}

uint32_t Mesh::next_sequence() {
    // Monotone across reboots: the boot incarnation (persistent, bumped before use) in the high half.
    const uint64_t inc = engine_.delivery().durable().incarnation();
    return static_cast<uint32_t>((inc & 0xFFFFU) << 16U) | (++seq_counter_ & 0xFFFFU);
}

bool Mesh::proxy_capable(MonoTime now) const {
    const member::MemberCredential &mc = engine_.identity().member();
    return engine_.identity().is_member() && mc.relay_allowed && mc.role >= 1 &&
           (state_ == State::Root || path_valid(now));
}

bool Mesh::route_via(const uint16_t *root_path, uint8_t n, uint32_t revision, delivery::PathSpec &out) const {
    if (n < 1 || n > k_max_root_path) {
        return false;
    }
    out = delivery::PathSpec{};
    out.origin = self_addr();
    out.dest = ShortAddr{root_path[0]};
    out.len = n; // root path entries incl. the candidate = hops from self
    for (uint8_t i = 0; i < n; ++i) {
        out.path[i] = root_path[n - 1U - i];
    }
    out.term = term();
    out.revision = PathRevision{revision};
    return true;
}

bool Mesh::route_to_root(delivery::PathSpec &out, MonoTime now) const {
    if (!path_valid(now) || path_n_ < 2) {
        return false;
    }
    out = delivery::PathSpec{};
    out.origin = self_addr();
    out.dest = ShortAddr{path_[0]};
    out.len = static_cast<uint8_t>(path_n_ - 1U);
    for (uint8_t i = 0; i < out.len; ++i) {
        out.path[i] = path_[path_n_ - 2U - i];
    }
    out.term = term();
    out.revision = PathRevision{rev_};
    return true;
}

Status Mesh::route_of(const DeviceId &dest, delivery::PathSpec &out, MonoTime now) const {
    if (state_ == State::Off) {
        return Status::NotFound;
    }
    if (is_root()) {
        return engine_.routes().path_to(dest, out, now) ? Status::Ok : Status::NotFound;
    }
    if (dest != root_id()) {
        return Status::NotFound; // other destinations: the route cache (ROUTE_QUERY answers land there)
    }
    return route_to_root(out, now) ? Status::Ok : Status::Busy; // no valid path (yet, or repairing): wait
}

Status Mesh::to_root(ByteView body, const delivery::PathSpec &route, MonoTime now) {
    return engine_.delivery().send_control(root_id(), route, body, now);
}

// ---- lifecycle ----
void Mesh::sync(MonoTime now) {
    const bool on = enabled_ && engine_.identity().is_member() && engine_.radio_state() == RadioState::Running;
    if (on && state_ == State::Off) {
        begin(now);
    } else if (!on && state_ != State::Off) {
        stop();
    }
}

void Mesh::begin(MonoTime now) {
    trickle_reset(now);
    if (is_root()) {
        state_ = State::Root;
        ready_since_ = now;
        schedule_beacon(now, 100); // say hello once at boot: neighbours need not solicit
        return;
    }
    state_ = State::Listen;
    disc_.begin(now, jitter(400), true, member::Discovery::k_budget, true);
}

void Mesh::stop() {
    state_ = State::Off;
    disc_.stop();
    cands_ = {};
    asks_ = {};
    att_ = Attach{};
    parent_ = -1;
    path_n_ = 0;
    rev_ = 0;
    lease_until_ = MonoTime{};
    lease_lapsed_ = true;
    ready_since_ = MonoTime::never();
    renew_at_ = renew_wait_ = attempt_at_ = beacon_at_ = trickle_at_ = spare_at_ = MonoTime::never();
    repairing_ = false;
    beacon_solicit_ = false;
    renew_tries_ = 0;
}

MonoTime Mesh::deadline() const {
    if (state_ == State::Off) {
        return MonoTime::never();
    }
    MonoTime d = earliest(disc_.deadline(), beacon_at_);
    if (state_ == State::Search) {
        d = earliest(d, attempt_at_);
    }
    d = earliest(d, att_.step == Step::Idle ? MonoTime::never() : att_.next_at);
    if (state_ == State::Ready || state_ == State::Root) {
        d = earliest(d, trickle_at_);
    }
    if (state_ == State::Ready) {
        d = earliest(d, earliest(earliest(renew_at_, renew_wait_), spare_at_));
        if (!lease_lapsed_) {
            d = earliest(d, lease_until_); // when the approved path stops being claimed valid
        }
    }
    for (const Ask &q : asks_) {
        if (q.used) {
            d = earliest(d, q.next_at);
        }
    }
    return d;
}

void Mesh::on_timer(MonoTime now) {
    sync(now);
    if (state_ == State::Off) {
        return;
    }
    if (!is_root()) {
        const member::Discovery::Act act = disc_.poll(now);
        if (state_ == State::Listen && !disc_.listening(now)) {
            state_ = State::Search;
            attempt_at_ = now;
        }
        if (act == member::Discovery::Act::Hello && state_ == State::Search) {
            send_beacon(true, now); // listen-first hint request (docs/07 §3)
        }
        if (act == member::Discovery::Act::Resumed) {
            attempt_at_ = now;
        }
        if (state_ == State::Search && now >= attempt_at_) {
            search_step(now);
        }
        attach_timer(now);
    }
    if (now >= beacon_at_) {
        const bool solicit = beacon_solicit_;
        beacon_at_ = MonoTime::never();
        beacon_solicit_ = false;
        send_beacon(solicit, now);
    }
    if ((state_ == State::Ready || state_ == State::Root) && now >= trickle_at_) {
        trickle(now);
    }
    if (state_ == State::Ready) {
        if (!lease_lapsed_ && now >= lease_until_) {
            lease_lapsed_ = true; // no beacons, no route: the root has not renewed; renewals go on (slowly)
        }
        if (now >= renew_wait_) {
            renew_wait_ = MonoTime::never();
            if (++renew_tries_ >= 3) { // the root does not answer: keep the parent, ask again slowly
                renew_tries_ = 0;
                renew_at_ = now + Duration::from_s(30);
                // Three unanswered rounds: the root may have lost its side of the end session (a restart).
                // Marking it suspect makes the next renewal set up a fresh one and register again.
                if (delivery::EndSession *es = engine_.delivery().sessions().find_peer(root_id())) {
                    es->suspect = true;
                    renew_at_ = now + Duration::from_s(1);
                }
            } else {
                renew(now);
            }
        } else if (now >= renew_at_ && att_.step == Step::Idle) {
            renew(now);
        }
        if (now >= spare_at_) {
            connect_spare(now);
        }
    }
    query_timer(now);
}

// ---- candidates ----
Mesh::Cand *Mesh::find_cand(const MacAddr &mac) {
    for (Cand &c : cands_) {
        if (c.used && c.mac == mac) {
            return &c;
        }
    }
    return nullptr;
}

// A free entry, else the least valuable unlinked one (never the parent or the candidate being tried).
Mesh::Cand *Mesh::alloc_cand(int keep) {
    Cand *victim = nullptr;
    for (std::size_t i = 0; i < cands_.size(); ++i) {
        Cand &c = cands_[i];
        if (!c.used) {
            return &c;
        }
        const int idx = static_cast<int>(i);
        if (idx == keep || idx == parent_ || idx == att_.cand || linked(c)) {
            continue;
        }
        if (victim == nullptr || c.heard < victim->heard) {
            victim = &c;
        }
    }
    if (victim != nullptr) {
        *victim = Cand{};
    }
    return victim;
}

const link::Neighbor *Mesh::neighbor_of(const Cand &c) const {
    return engine_.link().neighbors().find_mac(c.mac);
}

bool Mesh::linked(const Cand &c) const {
    const link::Neighbor *n = neighbor_of(c);
    return n != nullptr && n->cur.active && n->address.value() == c.addr;
}

uint32_t Mesh::score_of(const Cand &c, MonoTime now) const {
    return parent_score(c.n, c.q, c.inst.penalty(now));
}

// Measured candidates go by the integer score of docs/04 §6; an unmeasured one is never "best"
// against a measured one, and among unmeasured ones the lowest depth is tried first.
int Mesh::pick_candidate(MonoTime now) const {
    Candidate measured[k_cands];
    int index[k_cands];
    std::size_t m = 0;
    int shallow = -1;
    for (std::size_t i = 0; i < cands_.size(); ++i) {
        const Cand &c = cands_[i];
        if (!c.used || now < c.avoid_until || c.n == 0 || c.n > gen::limits::root_depth) {
            continue;
        }
        if (linked(c) && c.q.known()) {
            const link::Neighbor *n = neighbor_of(c);
            measured[m] = Candidate{n->device, c.n, c.q, c.inst.penalty(now)};
            index[m++] = static_cast<int>(i);
        } else if (shallow < 0 || c.n < cands_[static_cast<std::size_t>(shallow)].n ||
                   (c.n == cands_[static_cast<std::size_t>(shallow)].n &&
                    c.heard > cands_[static_cast<std::size_t>(shallow)].heard)) {
            shallow = static_cast<int>(i);
        }
    }
    const int best = pick_best(measured, m);
    return best >= 0 ? index[best] : shallow;
}

// ---- beacons ----
void Mesh::schedule_beacon(MonoTime now, uint16_t max_delay_ms) {
    const MonoTime at = now + Duration::from_ms(jitter(static_cast<uint16_t>(max_delay_ms + 1U)));
    if (beacon_at_.is_never() || at < beacon_at_) {
        beacon_at_ = at;
    }
}

void Mesh::send_beacon(bool solicit, MonoTime now) {
    const member::MemberCredential &mc = engine_.identity().member();
    Beacon b;
    b.term = term().value();
    if (solicit) {
        b.flags = k_beacon_solicit;
    } else if (state_ == State::Root) {
        b.flags = k_beacon_accepting;
        b.n = 1;
        b.path[0] = self_addr().value();
    } else if (path_valid(now)) {
        b.flags = mc.relay_allowed && mc.role >= 1 ? k_beacon_accepting : 0;
        b.revision = rev_;
        b.n = path_n_;
        std::copy(path_.begin(), path_.begin() + path_n_, b.path.begin());
    } else {
        return; // nothing to say without an approved path
    }
    std::array<uint8_t, wire::k_link_header_bytes + 11 + 2 * k_max_root_path> frame{};
    std::size_t len = 0;
    if (encode_beacon(b, link::domain_hint_of(engine_.identity().delegation().domain), MutByteView{frame}, len) !=
        Status::Ok) {
        return;
    }
    const Status st = engine_.transmit(MacAddr::broadcast(), ByteView{frame.data(), len},
                                       k_tag_mesh | (uint32_t{k_kind_beacon} << 8U), now);
    if (st == Status::Busy || st == Status::DriverResultUnknown) {
        ++stats_.tx_busy; // radio occupied/isolated: local, try again shortly
        beacon_at_ = now + k_busy_retry;
        beacon_solicit_ = solicit;
        return;
    }
    if (st == Status::Ok) {
        ++stats_.beacons_tx;
    }
}

void Mesh::on_beacon(const MacAddr &src, ByteView body, MonoTime now) {
    if (state_ == State::Off) {
        return;
    }
    Beacon b;
    if (decode_beacon(body, b) != Status::Ok || b.term != term().value()) {
        return;
    }
    ++stats_.beacons_rx;
    const member::MemberCredential &mc = engine_.identity().member();
    if ((b.flags & k_beacon_solicit) != 0) {
        // A hint request: answer once, after a short random delay (answers of neighbours coalesce).
        if ((state_ == State::Root || path_valid(now)) && mc.relay_allowed && mc.role >= 1) {
            schedule_beacon(now, 100);
        }
        return;
    }
    if (is_root() || b.n == 0 || (b.flags & k_beacon_accepting) == 0 ||
        check_candidate_path(self_addr(), b.path.data(), b.n, RootTerm{b.term}, term(), false) != Status::Ok) {
        return; // depth 21, a path through myself, another term: not a candidate (docs/04 §3 step 4)
    }
    Cand *c = find_cand(src);
    const bool fresh = c == nullptr;
    if (fresh) {
        c = alloc_cand(parent_);
        if (c == nullptr) {
            return; // three candidates are enough: nothing is evicted for a stranger
        }
        *c = Cand{};
        c->used = true;
        c->mac = src;
    }
    c->addr = b.path[b.n - 1U];
    c->revision = b.revision;
    c->n = b.n;
    std::copy(b.path.begin(), b.path.begin() + b.n, c->path.begin());
    c->heard = now;
    if (fresh && (state_ == State::Search || state_ == State::Listen)) {
        // A candidate that is ready: no reason to wait for the end of the listen or of a backoff.
        state_ = State::Search;
        if (disc_.in_backoff()) {
            disc_.wake(now, 0);
        }
        attempt_at_ = now;
    }
}

// ---- probes ----
// A session the peer no longer has (it restarted) is invisible to the MAC layer: frames are acked by the radio and
// dropped above it. Unanswered probes are the only sign; three in a row end the session so a fresh one is made.
void Mesh::drop_link(Cand &c) {
    if (const link::Neighbor *n = neighbor_of(c)) {
        (void)engine_.link().close(n->device);
    }
    c.probe_miss = 0;
    c.q = LinkQuality{};
}

void Mesh::send_probe(Cand &c, MonoTime now) {
    const link::Neighbor *n = neighbor_of(c);
    if (n == nullptr || !n->cur.active) {
        return;
    }
    if (!c.probe_wait.is_never() && now >= c.probe_wait && ++c.probe_miss >= 3) {
        drop_link(c);
        return;
    }
    const member::MemberCredential &mc = engine_.identity().member();
    Probe p;
    engine_.random(MutByteView{c.nonce});
    std::copy(c.nonce.begin(), c.nonce.end(), p.nonce.begin());
    p.sender = mc.address.value();
    p.receiver = c.addr;
    p.reply = false;
    const std::size_t free_frames = engine_.delivery().hop().free_frames();
    p.credit = static_cast<uint8_t>(free_frames * 255U / delivery::HopTx::k_frames);
    p.membership = mc.membership.value();
    std::array<uint8_t, 192> plain{};
    std::size_t len = 0;
    link::SealedFrame f;
    Status st = encode_probe(p, engine_.identity().delegation().domain, engine_.identity().self(),
                             MutByteView{plain}, len);
    if (st == Status::Ok) {
        st = engine_.link().seal(n->device, wire::FrameKind::Route, ByteView{plain.data(), len}, f, now);
    }
    if (st == Status::Ok) {
        st = engine_.transmit(n->mac, f.view(),
                              k_tag_mesh | (uint32_t{k_kind_probe} << 8U) | static_cast<uint32_t>(index_of(&c)), now);
    }
    if (st == Status::Ok) {
        ++stats_.probes_tx;
        c.probe_wait = now + k_probe_wait;
    } else if (st == Status::Busy || st == Status::DriverResultUnknown) {
        ++stats_.tx_busy;
        c.nonce.fill(0);
        attempt_at_ = earliest(attempt_at_, now + k_busy_retry); // Search/Attach re-enter and probe again
        if (att_.step == Step::Probe) {
            att_.next_at = now + k_busy_retry;
        }
    }
}

void Mesh::on_route_frame(const link::RxInfo &info, ByteView plain, MonoTime now) {
    Probe p;
    DeviceId issuer;
    if (state_ == State::Off || decode_probe(plain, p, issuer) != Status::Ok || issuer != info.peer) {
        return;
    }
    on_probe(info, p, now);
}

void Mesh::on_probe(const link::RxInfo &info, const Probe &p, MonoTime now) {
    ++stats_.probes_rx;
    if (!p.reply) { // answer under the session it came in on: bidirectional reach and our credit
        const link::Neighbor *n = engine_.link().neighbors().find_device(info.peer);
        if (n == nullptr || !n->cur.active || p.receiver != self_addr().value()) {
            return;
        }
        const member::MemberCredential &mc = engine_.identity().member();
        Probe r = p;
        r.sender = mc.address.value();
        r.receiver = p.sender;
        r.reply = true;
        r.credit = static_cast<uint8_t>(engine_.delivery().hop().free_frames() * 255U / delivery::HopTx::k_frames);
        r.membership = mc.membership.value();
        std::array<uint8_t, 192> plain{};
        std::size_t len = 0;
        link::SealedFrame f;
        if (encode_probe(r, engine_.identity().delegation().domain, engine_.identity().self(), MutByteView{plain},
                         len) == Status::Ok &&
            engine_.link().seal(n->device, wire::FrameKind::Route, ByteView{plain.data(), len}, f, now) ==
                Status::Ok) {
            (void)engine_.transmit(n->mac, f.view(), k_tag_mesh | (uint32_t{k_kind_probe} << 8U) | 0xFFU, now);
        }
        return;
    }
    Cand *c = find_cand(info.src);
    if (c == nullptr || c->probe_wait.is_never() ||
        !std::equal(c->nonce.begin(), c->nonce.end(), p.nonce.begin())) {
        return; // not the answer to a probe we sent
    }
    c->probe_wait = MonoTime::never();
    c->probe_miss = 0;
    c->nonce.fill(0);
    heard(*c, now);
    // The neighbour's queue pressure (credit) is its queue delay, an input of the parent score.
    c->q.record_queue_ms(static_cast<uint32_t>(255U - p.credit) * k_queue_ms_max / 255U);
    rf_sample(*c, true, now);
    if (att_.step == Step::Probe && att_.cand == index_of(c)) {
        attach_step(now);
    }
}

void Mesh::heard(Cand &c, MonoTime now) { c.heard = now; }

void Mesh::rf_sample(Cand &c, bool ok, MonoTime now) {
    c.q.record_attempt(ok);
    c.rf_streak = ok ? 0 : static_cast<uint8_t>(std::min<int>(c.rf_streak + 1, 250));
    if (!ok && index_of(&c) == parent_ && c.rf_streak >= k_rf_failures) {
        suspect(now);
    }
}

void Mesh::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    if (!is_mesh_tag(o.tag) || ((o.tag >> 8U) & 0xFFU) != k_kind_probe || state_ == State::Off) {
        return;
    }
    const uint32_t idx = o.tag & 0xFFU;
    if (idx >= k_cands || !cands_[idx].used) {
        return;
    }
    Cand &c = cands_[idx];
    if (o.result == port::TxResult::MacFailed) {
        rf_sample(c, false, now); // the only RF-loss sample of a probe (a missing reply is not)
        if (index_of(&c) == parent_ && state_ == State::Ready && c.rf_streak < k_rf_failures) {
            trickle_at_ = earliest(trickle_at_, now + Duration::from_ms(300)); // look again soon
        }
    } else if (o.result == port::TxResult::MacAcked) {
        c.rf_streak = 0;
        heard(c, now);
    }
}

// ---- Trickle: beacon and liveness ----
void Mesh::trickle_reset(MonoTime now) {
    trickle_i_ = Duration::from_ms(gen::defaults::routing::hello_min_ms);
    trickle_n_ = 0;
    trickle_at_ = now + Duration::from_ms(jitter(static_cast<uint16_t>(trickle_i_.to_ms())) + 1);
}

void Mesh::trickle(MonoTime now) {
    const Duration i = trickle_i_;
    trickle_i_ = i + i > k_hello_max ? k_hello_max : i + i;
    trickle_at_ = now + i;
    ++trickle_n_;
    const member::MemberCredential &mc = engine_.identity().member();
    if ((state_ == State::Root || path_valid(now)) && mc.relay_allowed && mc.role >= 1) {
        send_beacon(false, now);
    }
    if (state_ != State::Ready || parent_ < 0) {
        return;
    }
    Cand &p = cands_[static_cast<std::size_t>(parent_)];
    if (now - p.heard > k_silence) {
        suspect(now); // no authenticated sign of life for three hello intervals
        return;
    }
    if (!linked(p)) {
        suspect(now); // the link session is gone (peer restarted): repair like a dead parent
        return;
    }
    send_probe(p, now);
    for (std::size_t k = 0; k < cands_.size(); ++k) {
        Cand &c = cands_[k];
        if (c.used && static_cast<int>(k) != parent_ && linked(c) && trickle_n_ % 4 == 0) {
            send_probe(c, now); // spares are measured at a quarter of the rate
        }
    }
    const int best = [&] { // a voluntary move needs 20 % better and 30 s of holding (docs/04 §5)
        int b = -1;
        for (std::size_t k = 0; k < cands_.size(); ++k) {
            const Cand &c = cands_[k];
            if (static_cast<int>(k) != parent_ && c.used && linked(c) && c.q.known() && now >= c.avoid_until &&
                c.n <= gen::limits::root_depth &&
                (b < 0 || score_of(c, now) < score_of(cands_[static_cast<std::size_t>(b)], now))) {
                b = static_cast<int>(k);
            }
        }
        return b;
    }();
    if (best >= 0 && att_.step == Step::Idle &&
        should_switch(score_of(p, now), score_of(cands_[static_cast<std::size_t>(best)], now), now - parent_since_,
                      false)) {
        begin_attach(best, true, now);
    }
    if (spare_at_.is_never()) {
        spare_at_ = now + Duration::from_s(5);
    }
}

// Keeps up to two spare candidates linked (session + probes) so a repair needs no new handshake.
void Mesh::connect_spare(MonoTime now) {
    spare_at_ = MonoTime::never();
    if (state_ != State::Ready || att_.step != Step::Idle || engine_.link().exchange().busy()) {
        return;
    }
    for (std::size_t k = 0; k < cands_.size(); ++k) {
        Cand &c = cands_[k];
        if (c.used && static_cast<int>(k) != parent_ && !linked(c) && now >= c.avoid_until && now - c.heard < k_silence) {
            const Status st = engine_.link().connect(c.mac, now);
            if (st == Status::Ok) {
                c.avoid_until = now + Duration::from_s(30); // one try per candidate per 30 s (docs/06 §8 gate)
                return;
            }
            if (st == Status::Busy || st == Status::NoCapacity) {
                spare_at_ = now + Duration::from_s(2);
                return;
            }
            c.avoid_until = now + Duration::from_s(30);
        }
    }
}

void Mesh::on_link_up(const DeviceId &peer, MonoTime now) {
    const link::Neighbor *n = engine_.link().neighbors().find_device(peer);
    if (state_ == State::Off || n == nullptr) {
        return;
    }
    Cand *c = find_cand(n->mac);
    if (c == nullptr) {
        return;
    }
    c->addr = n->address.value();
    if (att_.step == Step::Link && att_.cand == index_of(c)) {
        attach_step(now);
    } else if (state_ == State::Ready) {
        send_probe(*c, now); // a spare: first measurement
    }
}

// ---- search and attach ----
void Mesh::search_step(MonoTime now) {
    attempt_at_ = MonoTime::never();
    if (att_.step != Step::Idle) {
        return;
    }
    if (!engine_.delivery().ready()) {
        attempt_at_ = now + Duration::from_ms(100); // boot records still loading (once per boot)
        return;
    }
    const int ci = pick_candidate(now);
    if (ci >= 0) {
        begin_attach(ci, false, now);
        return;
    }
    for (const Cand &c : cands_) { // nothing usable now: look again when the earliest avoidance ends
        if (c.used && c.avoid_until > now) {
            attempt_at_ = earliest(attempt_at_, c.avoid_until);
        }
    }
}

void Mesh::begin_attach(int ci, bool switching, MonoTime now) {
    att_ = Attach{};
    att_.cand = ci;
    att_.switching = switching;
    att_.next_at = now;
    att_.sequence = 0;
    if (!switching) {
        state_ = State::Attach;
    }
    attach_step(now);
}

void Mesh::attach_step(MonoTime now) {
    if (att_.cand < 0) {
        return;
    }
    Cand &c = cands_[static_cast<std::size_t>(att_.cand)];
    if (!linked(c)) {
        const bool budget = att_.switching || disc_.may_handshake();
        if (att_.step == Step::Link && now < att_.next_at) {
            return; // the handshake runs: on_link_up continues
        }
        if (!budget && att_.step != Step::Link) {
            attach_fail(now);
            return;
        }
        const Status st = engine_.link().connect(c.mac, now);
        if (st == Status::Ok) {
            if (!att_.switching && att_.step != Step::Link) {
                disc_.note_handshake();
            }
            att_.step = Step::Link;
            att_.next_at = now + k_link_wait;
        } else if (st == Status::Busy || st == Status::RateLimited || st == Status::NoCapacity) {
            att_.step = Step::Link;
            att_.next_at = now + (st == Status::RateLimited ? Duration::from_s(2) : Duration::from_ms(500));
        } else if (st != Status::Conflict) {
            attach_fail(now);
        }
        if (st != Status::Conflict) {
            return;
        }
    }
    // A link that was silent for a while must prove itself again before a registration relies on it: the peer
    // may have restarted and dropped its side of the session without the radio ever telling us.
    if (!c.q.known() || now - c.heard > k_probe_fresh) {
        if (att_.step != Step::Probe) {
            att_.step = Step::Probe;
            att_.tries = 0;
        }
        if (att_.tries >= 3) {
            attach_fail(now);
            return;
        }
        ++att_.tries;
        att_.next_at = now + k_probe_wait;
        send_probe(c, now);
        return;
    }
    delivery::PathSpec route;
    if (!route_via(c.path.data(), c.n, c.revision, route)) {
        attach_fail(now);
        return;
    }
    if (!engine_.delivery().has_session(root_id(), now)) {
        if (att_.step != Step::Session) {
            att_.step = Step::Session;
            att_.tries = 0;
        }
        const Status st = engine_.delivery().start_session(root_id(), route, now);
        if (st == Status::Ok) {
            att_.next_at = now + k_session_wait;
        } else if (st == Status::Busy) {
            engine_.delivery().want_slot(); // on_slot_free continues
            att_.next_at = now + k_slot_retry;
        } else if (st == Status::RateLimited) {
            att_.next_at = now + Duration::from_s(2) + Duration::from_ms(jitter(2000));
        } else if (++att_.tries >= 3) {
            attach_fail(now);
        } else {
            att_.next_at = now + Duration::from_s(1);
        }
        return;
    }
    if (att_.step != Step::Register && att_.step != Step::Confirm) {
        att_.step = Step::Register;
        att_.tries = 0;
        att_.sequence = next_sequence();
    }
    send_register(now);
}

void Mesh::send_register(MonoTime now) {
    Cand &c = cands_[static_cast<std::size_t>(att_.cand)];
    delivery::PathSpec route;
    std::array<uint8_t, 16> body{};
    std::size_t len = 0;
    Register r;
    r.sequence = att_.sequence;
    r.parent = c.addr;
    r.parent_revision = c.revision;
    r.term = term().value();
    if (!route_via(c.path.data(), c.n, c.revision, route) || encode(r, MutByteView{body}, len) != Status::Ok) {
        attach_fail(now);
        return;
    }
    const Status st = to_root(ByteView{body.data(), len}, route, now);
    if (st == Status::NoCapacity || st == Status::Busy || st == Status::NoRoute) {
        att_.next_at = now + Duration::from_ms(200); // TX pool full / no session with the first hop yet: local
        return;
    }
    if (st == Status::AuthPending) { // the end session went away: set it up again
        att_.step = Step::Session;
        att_.tries = 0;
        att_.next_at = now;
        attach_step(now);
        return;
    }
    if (st != Status::Ok) {
        attach_fail(now);
        return;
    }
    ++stats_.registers;
    if (++att_.tries > 4) {
        attach_fail(now);
        return;
    }
    att_.next_at = now + delivery::round_timeout(route.len);
}

void Mesh::send_ready(MonoTime now) {
    // The granted path: READY travels the new way (the reverse of the granted root path).
    delivery::PathSpec route;
    std::array<uint8_t, 16> body{};
    std::size_t len = 0;
    Ready r;
    r.term = term().value();
    r.revision = att_.revision;
    if (!route_via(att_.path.data(), static_cast<uint8_t>(att_.n - 1U), att_.revision, route) ||
        encode(r, MutByteView{body}, len) != Status::Ok) {
        attach_fail(now);
        return;
    }
    const Status st = to_root(ByteView{body.data(), len}, route, now);
    if (st == Status::NoCapacity || st == Status::Busy || st == Status::NoRoute) {
        att_.next_at = now + Duration::from_ms(200);
        return;
    }
    if (st != Status::Ok) {
        attach_fail(now);
        return;
    }
    ++stats_.readies;
    if (++att_.tries > 4) {
        attach_fail(now);
        return;
    }
    att_.next_at = now + delivery::round_timeout(route.len);
}

void Mesh::attach_timer(MonoTime now) {
    if (att_.step == Step::Idle || now < att_.next_at) {
        return;
    }
    switch (att_.step) {
    case Step::Idle:
        return;
    case Step::Link:
        if (linked(cands_[static_cast<std::size_t>(att_.cand)])) {
            attach_step(now);
        } else if (++att_.tries > 8) {
            attach_fail(now);
        } else {
            att_.step = Step::Link;
            attach_step(now);
        }
        return;
    case Step::Probe:
    case Step::Session:
        attach_step(now);
        return;
    case Step::Register:
        send_register(now);
        return;
    case Step::Confirm:
        send_ready(now);
        return;
    }
}

void Mesh::attach_fail(MonoTime now, bool soft) {
    if (att_.cand >= 0 && soft) {
        // The root answered: it only wants the parent approved first (a restarted root rebuilds top down).
        cands_[static_cast<std::size_t>(att_.cand)].avoid_until = now + Duration::from_s(3) + Duration::from_ms(jitter(3000));
    } else if (att_.cand >= 0) {
        Cand &c = cands_[static_cast<std::size_t>(att_.cand)];
        if (att_.step == Step::Probe) {
            drop_link(c); // three probes unanswered: the session is stale, the next try starts a new one
        } else if ((att_.step == Step::Register || att_.step == Step::Confirm) && c.fails >= 1) {
            // Sent four times, twice in a row, never answered: the root may have lost its end session (a restart).
            // A fresh one costs one handshake; retrying a dead one costs the same airtime for nothing. (One
            // silent round alone is more often a busy root.)
            if (delivery::EndSession *es = engine_.delivery().sessions().find_peer(root_id())) {
                es->suspect = true;
            }
        }
        c.fails = static_cast<uint8_t>(std::min<int>(c.fails + 1, 12));
        // Jittered: many nodes that lost the root together must not come back in step (one handshake slot there).
        c.avoid_until = now + Duration::from_s(std::min<int>(5 * c.fails, 60)) + Duration::from_ms(jitter(8000));
    }
    ++stats_.attach_failed;
    att_ = Attach{};
    if (state_ == State::Attach) {
        state_ = State::Search;
    }
    attempt_at_ = now; // the next candidate at once; search_step waits for avoidance to end
}

void Mesh::on_session(const DeviceId &peer, Status st, MonoTime now) {
    if (state_ == State::Off || att_.step != Step::Session || peer != root_id()) {
        return;
    }
    if (st == Status::Ok) {
        attach_step(now);
    } else if (++att_.tries >= 3) {
        attach_fail(now);
    } else {
        att_.next_at = now + Duration::from_s(2); // RateLimited (30 s gate) and friends: try again
    }
}

void Mesh::on_slot_free(MonoTime now) {
    if (state_ == State::Off) {
        return;
    }
    if (att_.step == Step::Session) {
        attach_step(now);
    }
    if (state_ == State::Ready && spare_at_.is_never()) {
        spare_at_ = now;
    }
}

// ---- root records ----
void Mesh::on_control(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now) {
    if (state_ == State::Off || !is_mesh_record(body)) {
        return;
    }
    if (is_root()) {
        engine_.routes().on_control(peer, reply, body, now);
        return;
    }
    if (peer != root_id()) {
        return; // only the root speaks to a node about its path
    }
    LeaseRec l;
    Answer a;
    if (decode(body, l) == Status::Ok) {
        on_lease(l, now);
    } else if (decode(body, a) == Status::Ok) {
        on_answer(a, now);
    }
}

void Mesh::on_lease(const LeaseRec &l, MonoTime now) {
    ++stats_.leases;
    if (l.term != term().value() && l.status == Status::Ok) {
        return;
    }
    expected_rev_ = l.expected_revision != 0 ? l.expected_revision : expected_rev_;
    if (l.push) { // the root moved the subtree above us: same parent, new path
        if (state_ == State::Ready && parent_ >= 0 && l.status == Status::Ok && l.revision >= rev_ && l.n >= 2 &&
            l.path[l.n - 1U] == self_addr().value() &&
            l.path[l.n - 2U] == cands_[static_cast<std::size_t>(parent_)].addr && !(l.revision == rev_ && l.n == path_n_)) {
            std::copy(l.path.begin(), l.path.begin() + l.n, path_.begin());
            path_n_ = l.n;
            rev_ = l.revision;
            lease_until_ = now + (Duration::from_ms(l.lease_ms) - k_lease_margin);
    lease_lapsed_ = false;
            engine_.delivery().invalidate_routes();
            engine_.delivery().routes_changed(now);
            trickle_reset(now);
            schedule_beacon(now, 50);
        }
        return;
    }
    if (att_.step == Step::Register && att_.cand >= 0) {
        Cand &c = cands_[static_cast<std::size_t>(att_.cand)];
        if (l.status != Status::Ok) {
            // A stale advertisement is refused with the parent's current revision: one immediate retry.
            if (l.status == Status::NoRoute && l.revision != 0 && l.revision != c.revision && att_.tries < 3) {
                c.revision = l.revision;
                send_register(now);
            } else if (l.status == Status::NoRoute || l.status == Status::Busy) {
                attach_fail(now, true); // the parent is not (yet) approved itself: a few seconds, not a failure
            } else {
                attach_fail(now);
            }
            return;
        }
        if (l.n < 2 || l.path[l.n - 1U] != self_addr().value() || l.path[l.n - 2U] != c.addr ||
            l.path[0] != c.path[0]) {
            attach_fail(now); // a grant that is not for this parent
            return;
        }
        att_.revision = l.revision;
        att_.n = l.n;
        std::copy(l.path.begin(), l.path.begin() + l.n, att_.path.begin());
        att_.step = Step::Confirm;
        att_.tries = 0;
        send_ready(now);
        return;
    }
    if (att_.step == Step::Confirm) {
        if (l.status == Status::Ok && l.revision == att_.revision && l.n >= 2) {
            commit(l, now);
        } else if (l.status != Status::Ok) {
            attach_fail(now);
        }
        return;
    }
    if (state_ != State::Ready) {
        return;
    }
    // Renewal answer.
    renew_wait_ = MonoTime::never();
    renew_tries_ = 0;
    if (l.status != Status::Ok) {
        lose_path(now); // the root does not know this approval any more (restart, new term): register again
        return;
    }
    if (l.n >= 2 && l.path[l.n - 1U] == self_addr().value() && l.revision >= rev_) {
        std::copy(l.path.begin(), l.path.begin() + l.n, path_.begin());
        path_n_ = l.n;
        rev_ = l.revision;
    }
    lease_until_ = now + (Duration::from_ms(l.lease_ms) - k_lease_margin);
    lease_lapsed_ = false;
    renew_at_ = now + k_lease_refresh + Duration::from_ms(jitter(6000));
    if (parent_ >= 0) {
        heard(cands_[static_cast<std::size_t>(parent_)], now);
    }
}

void Mesh::commit(const LeaseRec &l, MonoTime now) {
    const bool moved = parent_ != att_.cand;
    std::copy(l.path.begin(), l.path.begin() + l.n, path_.begin());
    path_n_ = l.n;
    rev_ = l.revision;
    lease_until_ = now + (Duration::from_ms(l.lease_ms) - k_lease_margin);
    lease_lapsed_ = false;
    parent_ = att_.cand;
    Cand &p = cands_[static_cast<std::size_t>(parent_)];
    p.fails = 0;
    p.rf_streak = 0;
    heard(p, now);
    att_ = Attach{};
    state_ = State::Ready;
    attempt_at_ = MonoTime::never();
    parent_since_ = now;
    if (ready_since_.is_never()) {
        ready_since_ = now;
    }
    if (repairing_) {
        stats_.last_repair_ms = static_cast<uint64_t>((now - repair_since_).to_ms());
        repairing_ = false;
    }
    renew_at_ = now + k_lease_refresh + Duration::from_ms(jitter(6000));
    renew_wait_ = MonoTime::never();
    renew_tries_ = 0;
    trickle_reset(now);
    schedule_beacon(now, 30); // children waiting for a ready parent hear it at once
    spare_at_ = now + Duration::from_s(1);
    if (moved) {
        engine_.delivery().invalidate_routes(); // stitched routes were built on the old path
    }
    engine_.delivery().routes_changed(now);
}

void Mesh::renew(MonoTime now) {
    renew_at_ = MonoTime::never();
    delivery::PathSpec route;
    std::array<uint8_t, 16> body{};
    std::size_t len = 0;
    Ready r;
    r.term = term().value();
    r.revision = rev_;
    if (path_n_ < 2 || !route_via(path_.data(), static_cast<uint8_t>(path_n_ - 1U), rev_, route) ||
        encode(r, MutByteView{body}, len) != Status::Ok) {
        return;
    }
    const Status st = to_root(ByteView{body.data(), len}, route, now);
    if (st == Status::Ok) {
        ++stats_.readies;
        renew_wait_ = now + delivery::round_timeout(route.len);
    } else if (st == Status::AuthPending) {
        lose_path(now); // no end session with the root any more: attach again
    } else {
        renew_wait_ = now + Duration::from_ms(500); // TX pool / first hop busy: local, look again
    }
}

// The root no longer knows our approval (or our end session is gone): register again with the same parent.
void Mesh::lose_path(MonoTime now) {
    if (parent_ < 0) {
        return;
    }
    const int ci = parent_;
    repairing_ = true;
    repair_since_ = now;
    parent_ = -1;
    state_ = State::Search;
    lease_until_ = MonoTime{};
    lease_lapsed_ = true;
    begin_attach(ci, false, now);
}

// The parent is gone by the rules of docs/04 §5: three RF failures, or three hello intervals of silence.
void Mesh::suspect(MonoTime now) {
    if (state_ != State::Ready || parent_ < 0) {
        return;
    }
    ++stats_.suspects;
    Cand &p = cands_[static_cast<std::size_t>(parent_)];
    p.inst.note_change(now);
    p.avoid_until = now + Duration::from_s(30); // a dead link does not wait for the hold time, but is not retried at once
    repairing_ = true;
    repair_since_ = now;
    parent_ = -1;
    state_ = State::Search;
    lease_until_ = MonoTime{}; // the old path serves no more: sends wait for the new one
    lease_lapsed_ = true;
    att_ = Attach{};
    disc_.wake(now, 0);
    attempt_at_ = now;
    schedule_beacon(now, 0);
    beacon_solicit_ = true; // ask for parents at once when no spare is linked
}

// ---- frames done at the hop layer: link quality and repair ----
void Mesh::on_frame_done(const delivery::FrameDone &f, delivery::HopEnd end, MonoTime now) {
    if (f.kind == delivery::OwnerKind::Tunnel) {
        engine_.proxy().on_frame_done(f, end, now);
        return;
    }
    if (state_ == State::Off) {
        return;
    }
    Cand *c = find_cand(f.mac);
    if (c == nullptr) {
        return;
    }
    if (end == delivery::HopEnd::Accepted) {
        for (uint8_t i = 1; i < f.attempts && i < 3; ++i) {
            c->q.record_attempt(false); // earlier attempts of this frame got no HOP_ACK
        }
        c->q.record_attempt(true);
        c->rf_streak = 0;
        heard(*c, now);
    } else if (end == delivery::HopEnd::Failed && f.attempts >= 3) {
        // Three attempts, no HOP_ACK: targeted RF failures. (Failed after BUSY deferrals has fewer
        // attempts and is not counted.)
        for (int i = 0; i < 3; ++i) {
            c->q.record_attempt(false);
        }
        c->rf_streak = static_cast<uint8_t>(std::min<int>(c->rf_streak + 3, 250));
        if (index_of(c) == parent_ && c->rf_streak >= k_rf_failures) {
            suspect(now);
        }
    }
}

// ---- ROUTE_QUERY ----
namespace {
constexpr uint8_t k_refused = 255; // Ask::tries: the root said no; the entry only delays the next question
}

void Mesh::want_route(const DeviceId &dest, MonoTime now) {
    if (is_root() || state_ != State::Ready || !path_valid(now) || dest == root_id() || att_.step != Step::Idle) {
        return;
    }
    Ask *slot = nullptr;
    for (Ask &q : asks_) {
        if (q.used && q.dest == dest) {
            return; // in flight (or a recent refusal): asked once per round
        }
        if (!q.used && slot == nullptr) {
            slot = &q;
        }
    }
    if (slot == nullptr) {
        return; // two queries at a time: the sender's WaitRoute asks again
    }
    *slot = Ask{};
    slot->used = true;
    slot->dest = dest;
    slot->qid = next_qid_++;
    if (next_qid_ == 0) {
        next_qid_ = 1;
    }
    slot->next_at = now;
    query_timer(now);
}

void Mesh::query_timer(MonoTime now) {
    for (Ask &q : asks_) {
        if (!q.used || now < q.next_at) {
            continue;
        }
        delivery::PathSpec route;
        if (q.tries == k_refused || q.tries >= 3 || !route_to_root(route, now)) {
            q = Ask{}; // refusal remembered long enough, or unanswered: the next miss asks again
            continue;
        }
        route::Query m;
        m.qid = q.qid;
        m.dest = q.dest;
        std::array<uint8_t, 48> body{};
        std::size_t len = 0;
        if (encode(m, MutByteView{body}, len) != Status::Ok) {
            q = Ask{};
            continue;
        }
        if (to_root(ByteView{body.data(), len}, route, now) == Status::Ok) {
            ++q.tries;
            ++stats_.queries;
            q.next_at = now + delivery::round_timeout(route.len);
        } else {
            q.next_at = now + Duration::from_ms(200); // no session yet / TX pool full: local
        }
    }
}

void Mesh::on_answer(const Answer &a, MonoTime now) {
    ++stats_.answers;
    for (Ask &q : asks_) {
        if (!q.used || q.qid != a.qid) {
            continue;
        }
        if (a.status != Status::Ok) {
            q.tries = k_refused;
            q.next_at = now + k_negative_life;
            return;
        }
        delivery::PathSpec ps;
        std::size_t n = 0;
        if (!path_valid(now) || a.path[a.n - 1U] != a.dest ||
            stitch_route(path_.data(), path_n_, a.path.data(), a.n, ps.path.data(), ps.path.size(), n) != Status::Ok ||
            n == 0) {
            q = Ask{};
            return;
        }
        ps.origin = self_addr();
        ps.dest = ShortAddr{a.dest};
        ps.len = static_cast<uint8_t>(n);
        ps.term = term();
        ps.revision = PathRevision{std::max(rev_, a.revision)};
        const Duration left = lease_until_ - now;
        const DeviceId dest = q.dest;
        q = Ask{};
        (void)engine_.delivery().install_route(dest, ps, now + (left < k_route_life ? left : k_route_life));
        engine_.delivery().routes_changed(now);
        return;
    }
}

} // namespace lm::route
