#include "root/channel_coordinator.hpp"

#include <algorithm>

#include "core/engine.hpp"
#include "security/crypto.hpp"

namespace lm::root {
namespace {

constexpr uint16_t k_first = 2, k_end = 66; // member addresses = ledger slots + 2 (at most 64)
constexpr unsigned k_batch = 8;              // records per pacing step: 64 members in 4 s
constexpr Duration k_step = Duration::from_ms(500), k_round = Duration::from_s(4), k_recover_round = Duration::from_s(60);
constexpr Duration k_abort_cooldown = Duration::from_s(600), k_retained_cooldown = Duration::from_s(300);
constexpr Duration k_survey_max = Duration::from_s(1200);
constexpr Duration k_recover_max = Duration::from_s(1800); // RECOVERING ends here at the latest (FIX10-D6)
constexpr Duration k_abort_ledger_wait = Duration::from_s(30); // a restored ABORT waits this long for the ledger to name its members
constexpr Duration k_visit_gap = Duration::from_ms(60000 / gen::defaults::channel::max_visits_per_minute); // per node and minute
constexpr uint64_t k_lead_ms = 6000, k_min_arm_ms = 2500; // window start ahead of the request; the visitor must hear it this early
constexpr uint16_t k_tol_ms = 100, k_tol_wide_ms = 200;   // clock tolerance of a visit; the retry after TIME_UNCERTAIN is wider
constexpr uint8_t k_probes = 8, k_visit_tries = 4;

Duration ms(uint64_t v) { return Duration::from_ms(static_cast<int64_t>(v)); }

// Refusals that no repeat can cure (a Busy or a missing session can).
bool hard_refusal(Status s) {
    return s == Status::TimeUncertain || s == Status::Conflict || s == Status::NetworkMismatch ||
           s == Status::RfProfileUnapproved || s == Status::Expired || s == Status::RecoveryRequired;
}

} // namespace

// ---- membership view ---------------------------------------------------------------------------------
bool Coordinator::attached(uint16_t addr, MonoTime now) const {
    RouteGrant g;
    return engine_.routes().topology().path_from_root(ShortAddr{addr}, now.to_ms(), g) == Status::Ok;
}

unsigned Coordinator::children_of(uint16_t addr, MonoTime now) const {
    unsigned n = 0;
    for (uint16_t a = k_first; a < k_end; ++a) {
        ShortAddr par;
        n += attached(a, now) && engine_.routes().topology().parent_of(ShortAddr{a}, par) == Status::Ok && par.value() == addr;
    }
    return n;
}

bool Coordinator::device_at(uint16_t addr, DeviceId &out) const {
    const Entry &e = engine_.ledger().entry(addr - k_first);
    const delivery::EndSession *s = engine_.delivery().end_session_at(ShortAddr{addr});
    if (e.state == EntryState::Active && e.address.value() == addr) {
        out = e.device;
    } else if (s != nullptr && s->rec.active()) {
        out = s->peer;
    } else {
        return false;
    }
    return true;
}

bool Coordinator::member_of(const DeviceId &peer, uint16_t &addr) const {
    const delivery::EndSession *s = engine_.delivery().sessions().find_peer(peer);
    addr = s != nullptr ? s->peer_addr.value() : 0;
    return s != nullptr && s->rec.active() && addr >= k_first && addr < k_end &&
           engine_.routes().topology().is_admitted(s->peer_addr);
}

// The identity behind an address: SHA-256 over (address, DeviceId, assignment, membership) of the CURRENT holder, but
// only when `dev` is that holder (a factory-provisioned member without a ledger entry counts with generations 0).
// A plan binds this tag per required address when it is made; whoever sits at the address later has another tag
// (FIX3-D7).
bool Coordinator::tag_for(uint16_t addr, const DeviceId &dev, Tag &out) const {
    const Entry &e = engine_.ledger().entry(addr - k_first);
    uint64_t a = 0, m = 0;
    if (e.state == EntryState::Active && e.address.value() == addr) {
        if (!(e.device == dev)) {
            return false;
        }
        a = e.assignment;
        m = e.membership;
    } else {
        const delivery::EndSession *s = engine_.delivery().end_session_at(ShortAddr{addr});
        if (s == nullptr || !s->rec.active() || !(s->peer == dev)) {
            return false;
        }
    }
    std::array<uint8_t, 2 + 32 + 16> in{};
    in[0] = static_cast<uint8_t>(addr >> 8U);
    in[1] = static_cast<uint8_t>(addr);
    std::copy(dev.bytes.begin(), dev.bytes.end(), in.begin() + 2);
    for (unsigned i = 0; i < 8; ++i) {
        in[34 + i] = static_cast<uint8_t>(a >> (56U - 8U * i));
        in[42 + i] = static_cast<uint8_t>(m >> (56U - 8U * i));
    }
    Sha256Digest h{};
    if (sec::sha256(ByteView{in}, h) != Status::Ok) {
        return false;
    }
    std::copy(h.begin(), h.begin() + out.size(), out.begin());
    return true;
}

// Is the current holder of `addr` the participant this plan was made for?
bool Coordinator::is_participant(uint16_t addr, const DeviceId &dev) const {
    Tag t{};
    return bound_ && addr >= k_first && addr < k_end && tag_for(addr, dev, t) && t == part_[addr - k_first];
}

// After a restart the tags are gone (RAM): they are rebuilt from the holders now, but only when those are exactly
// the devices the persisted plan's participant hash names. Any difference binds nobody - fail closed.
void Coordinator::rebind() {
    if (bound_ || required_ == 0) {
        return;
    }
    Sha256Digest h{};
    std::array<Tag, 64> tags{};
    for (uint16_t a = k_first; a < k_end; ++a) {
        if ((required_ & bit(a)) == 0) {
            continue;
        }
        DeviceId dev;
        if (!device_at(a, dev) || !tag_for(a, dev, tags[a - k_first])) {
            return;
        }
        std::array<uint8_t, 34> part{};
        part[0] = static_cast<uint8_t>(a >> 8U);
        part[1] = static_cast<uint8_t>(a);
        std::copy(dev.bytes.begin(), dev.bytes.end(), part.begin() + 2);
        if (sec::sha256_parts(ByteView{h}, ByteView{part}, h) != Status::Ok) {
            return;
        }
    }
    if (h == plan_.participants) {
        part_ = tags;
        bound_ = true;
    }
}

Status Coordinator::send_to(uint16_t addr, ByteView rec, MonoTime now) {
    DeviceId dev;
    delivery::PathSpec route;
    if (!device_at(addr, dev)) {
        return Status::AuthPending;
    }
    if (!engine_.routes().path_to_addr(ShortAddr{addr}, route, now)) {
        return Status::NoRoute;
    }
    const Status st = engine_.delivery().send_control(dev, route, rec, now);
    if (st == Status::AuthPending) { // no end session right now: open one, the next round sends
        (void)engine_.delivery().start_session(dev, route, now);
    }
    return st;
}

void Coordinator::changed(MonoTime now) { engine_.chan().persist_now(now); }

void Coordinator::set_state(CState s, Why why) {
    if (s != state_) { // (a node's own module reports mode << 8 | detail; the coordinator's events carry 0x10000)
        engine_.raise(LM_EVENT_CHANNEL, 0x10000U | static_cast<uint32_t>(s) << 8U | static_cast<uint32_t>(why));
    }
    state_ = s;
    why_ = why;
}

// ---- gates and commands ----------------------------------------------------------------------------------
bool Coordinator::may_start(bool operator_override, MonoTime now) {
    if (state_ != CState::Monitor) {
        return false;
    }
    if (frozen_) {
        why_ = Why::Frozen;
        return false;
    }
    if (operator_override) { // explicit administrator request: audited by the CHANNEL event, not rate limited
        return true;
    }
    unsigned recent = 0;
    for (uint8_t i = 0; i < std::min<uint8_t>(n_changes_, 4); ++i) {
        recent += now.to_ms() / 1000 - changes_[i] < 86400;
    }
    if (now < cool_until_ || recent >= gen::defaults::channel::daily_change_limit) {
        why_ = now < cool_until_ ? Why::Cooldown : Why::DailyLimit;
        return false;
    }
    return true;
}

Reply Coordinator::request(uint32_t action, uint64_t expected_revision, MonoTime now) {
    if (!engine_.chan().loaded() || engine_.chan().holds_mesh()) {
        return Reply{Status::Busy, 0, 0};
    }
    if (expected_revision != policy_rev_) {
        return Reply{Status::Conflict, 0, 0}; // stale policy revision (compare-and-set)
    }
    if (action == LM_CHANNEL_RECALCULATE) {
        if (frozen_ || state_ != CState::Monitor) {
            why_ = frozen_ ? Why::Frozen : why_;
            return Reply{frozen_ ? Status::Conflict : Status::Busy, 0, 0};
        }
        start_survey(now);
        return Reply{Status::Ok, 0, 0};
    }
    if (action > LM_CHANNEL_RECALCULATE) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    const bool freeze = action == LM_CHANNEL_FREEZE;
    if (freeze != frozen_) {
        freeze_seq_ = engine_.chan().next_save_seq(); // (read before any write of this change can start)
        if (freeze_op_ == 0) { // a change made while the last one is not durable yet: one operation, for the latest state
            freeze_op_ = engine_.next_control_op();
        }
        frozen_ = freeze;
        ++policy_rev_;
        if (freeze && state_ == CState::Survey) {
            end_survey(now); // a measurement in progress is dropped: no plan follows
            set_state(CState::Monitor, Why::Frozen);
        } else if (freeze && state_ == CState::Preparing) {
            abort_plan(Why::Frozen, now); // not yet committed: nothing to complete. COMMITTED and later: never cancelled
        }
        changed(now);
        return Reply{Status::Ok, freeze_op_, 0}; // applied now; durable when LM_EVENT_OPERATION(freeze_op_) arrives (FIX10-D9)
    }
    return Reply{Status::Ok, freeze_op_, 0}; // no change: still the pending operation of the state asked for, if any
}

// A record write finished (owner thread). The freeze is durable when a write that began after it was set succeeded.
void Coordinator::on_written(uint32_t seq, bool ok, MonoTime) {
    if (ok && freeze_op_ != 0 && seq >= freeze_seq_) {
        engine_.emit_event(LM_EVENT_OPERATION, 0, freeze_op_, nullptr);
        freeze_op_ = 0;
    }
}

// ---- plans ---------------------------------------------------------------------------------------------
Status Coordinator::begin_plan(uint8_t new_ch, MonoTime now) {
    if ((engine_.identity().delegation().permissions & member::k_perm_channel) == 0) {
        return Status::AuthRejected; // FIX12-D2: the delegation carries no channel permission: no plan is originated
    }
    channel::Channel &ch = engine_.chan();
    if (!ch.loaded() || ch.committed() || ch.have_plan()) {
        return Status::Busy;
    }
    if (new_ch == ch.current() || new_ch < 1 || new_ch > 13 || ((engine_.config().rf.allowed_channels_mask >> new_ch) & 1U) == 0) {
        return Status::InvalidArgument;
    }
    ChannelEpoch next;
    if (!next_generation(std::max(ch.epoch(), plan_.epoch), 0xFFFFFFFFU, next)) {
        return Status::RecoveryRequired; // epochs never wrap
    }
    // The participant snapshot: attached members are required, unless they sleep (deferred). A critical receiver
    // that cannot be reached defers the whole plan unless the operator accepted that explicitly (docs/20 §9).
    uint64_t required = 0, deferred = 0;
    Sha256Digest h{};
    std::array<Tag, 64> tags{};
    for (uint16_t a = k_first; a < k_end; ++a) {
        if (!engine_.routes().topology().is_admitted(ShortAddr{a})) {
            continue;
        }
        const bool critical = (critical_ & bit(a)) != 0;
        // A member that sleeps by policy is deferred: the root's schedule view says so (S16), the bench flag only adds.
        const bool sleepy = (sleepy_ & bit(a)) != 0 || engine_.power().sleepy_member(ShortAddr{a}, now);
        if (attached(a, now) && (!sleepy || critical)) {
            required |= bit(a);
            std::array<uint8_t, 34> part{};
            DeviceId dev;
            if (!device_at(a, dev) || !tag_for(a, dev, tags[a - k_first])) {
                return Status::AuthPending; // the holder changes under us: not a participant we can name
            }
            part[0] = static_cast<uint8_t>(a >> 8U);
            part[1] = static_cast<uint8_t>(a);
            std::copy(dev.bytes.begin(), dev.bytes.end(), part.begin() + 2);
            if (sec::sha256_parts(ByteView{h}, ByteView{part}, h) != Status::Ok) {
                return Status::RecoveryRequired;
            }
        } else if (critical && !defer_ok_) {
            why_ = Why::CriticalAsleep;
            return Status::PeerAsleep;
        } else {
            deferred |= bit(a);
        }
    }
    if (required == 0) {
        why_ = Why::NoMembers;
        return Status::NotFound;
    }
    plan_ = channel::Plan{};
    engine_.random(MutByteView{plan_.id.bytes});
    plan_.term = engine_.identity().member().root_term;
    plan_.epoch = next;
    plan_.old_ch = ch.current();
    plan_.new_ch = new_ch;
    plan_.switch_root_ms = now.to_ms() + prepare_timeout_ms_ + commit_lead_ms_;
    plan_.max_err_ms = max_err_ms_;
    plan_.settle_ms = static_cast<uint32_t>(gen::defaults::channel::settle_ms);
    plan_.policy_rev = policy_rev_;
    plan_.participants = h;
    required_ = required;
    part_ = tags;
    bound_ = true;
    deferred_ = deferred;
    ready_ = stored_ = applied_ = 0;
    self_ev_ = 0;
    plan_start_ = now;
    cursor_ = 0;
    ++stats_.plans;
    set_state(CState::Preparing, Why::None);
    tick_at_ = now;
    changed(now);
    return Status::Ok;
}

Status Coordinator::plan_to(uint8_t channel_no, MonoTime now) {
    if (!may_start(true, now)) {
        return state_ == CState::Monitor ? Status::Conflict : Status::Busy;
    }
    return begin_plan(channel_no, now);
}

Status Coordinator::rollback(MonoTime now) {
    if (rollback_to_ == 0) {
        return Status::NotFound;
    }
    if (frozen_) {
        why_ = Why::Frozen;
        return Status::Conflict;
    }
    if (state_ != CState::Monitor && state_ != CState::Settling && state_ != CState::Recovering) {
        return Status::Busy;
    }
    set_state(CState::Monitor, Why::None); // the last plan is finished as far as this root will go
    return begin_plan(rollback_to_, now);
}

void Coordinator::abort_plan(Why why, MonoTime now) {
    // H8: once the root's own COMMIT is being written (or is durable) the plan can only be followed. Aborting here would
    // send ABORT to the members while the root goes on to switch alone, and report ABORTED for a switched root.
    if (state_ == CState::Preparing && engine_.chan().commit_started()) {
        tick_at_ = now + ms(20); // the write answers with a receipt (or fails and the tick decides again)
        return;
    }
    ++stats_.aborts;
    abort_since_ = now;
    set_state(CState::Aborted, why);
    cursor_ = 0;
    tick_at_ = now;
    cool_until_ = now + k_abort_cooldown;
    changed(now);
}

// One batch of the current round: PLAN records to the members in `missing`, k_batch at a time.
void Coordinator::send_round(channel::Phase phase, uint64_t missing, MonoTime now) {
    channel::PlanRec rec;
    rec.phase = phase;
    rec.plan = plan_;
    for (unsigned sent = 0; cursor_ < 64 && sent < k_batch;) {
        const uint16_t a = static_cast<uint16_t>(k_first + cursor_++);
        if ((missing & bit(a)) != 0) {
            DeviceId dev;
            if (device_at(a, dev) && is_participant(a, dev)) { // never a plan to a device that took the address later
                (void)send_to(a, rec, now); // a refusal by the stack is local: the next round asks again
            }
            ++sent;
        }
    }
    tick_at_ = now + k_step;
    if (cursor_ >= 64) { // the round is complete
        cursor_ = 0;
        tick_at_ = now + (state_ == CState::Recovering ? k_recover_round : k_round);
    }
}

void Coordinator::plan_tick(MonoTime now) {
    channel::Channel &ch = engine_.chan();
    if (!bound_ && state_ == CState::Recovering && engine_.ledger().ready()) {
        rebind();
    }
    channel::PlanRec rec;
    rec.plan = plan_;
    switch (state_) {
    case CState::Preparing: {
        if (frozen_ && !ch.commit_started()) { // (request() aborts at once; this catches a write that failed after it)
            abort_plan(Why::Frozen, now);
            return;
        }
        if (now >= plan_start_ + ms(prepare_timeout_ms_)) {
            abort_plan(Why::PrepareTimeout, now); // a missing READY is never dropped from the denominator
            return;
        }
        const bool members_ready = (required_ & ~ready_) == 0;
        if (self_ev_ < 2 && (self_ev_ < 1 || members_ready)) { // our own PREPARE, then (all READY) our own COMMIT
            rec.phase = self_ev_ < 1 ? channel::Phase::Prepare : channel::Phase::Commit;
            tick_at_ = now + (ch.local_plan(rec, now) == Status::Ok ? ms(200) : ms(20)); // the receipt wakes us earlier
        } else if (members_ready) { // the root's COMMIT is durable: only now does anybody hear COMMIT
            ++stats_.commits;
            set_state(CState::Committed, Why::None);
            cursor_ = 0;
            tick_at_ = now;
            changed(now);
            return;
        }
        if (!members_ready) {
            send_round(channel::Phase::Prepare, required_ & ~ready_, now);
        }
        return;
    }
    case CState::Committed: // waits for our own switch (Channel calls on_local_switch)
        if ((required_ & ~stored_) != 0) {
            send_round(channel::Phase::Commit, required_ & ~stored_, now);
        } else {
            tick_at_ = MonoTime::never();
        }
        return;
    case CState::Switching:
    case CState::Settling:
    case CState::Recovering: {
        if (state_ == CState::Recovering && now >= rec_since_ + k_recover_max) {
            // FIX10-D6: some required member never confirmed. It is not undone and not forgotten (the view keeps
            // required / applied); it follows through its own search and State report. The coordinator is free again.
            set_state(CState::Monitor, Why::Partial);
            tick_at_ = MonoTime::never();
            changed(now);
            return;
        }
        const MonoTime settle_at = switched_at_ + ms(plan_.settle_ms);
        if (state_ == CState::Switching && now >= switched_at_ + ms(uint64_t{plan_.max_err_ms} + 500)) {
            set_state(CState::Settling, Why::None);
        }
        if (state_ != CState::Recovering && now >= settle_at) {
            finish_settle(now);
        } else if ((required_ & ~applied_) != 0) {
            send_round(channel::Phase::Commit, required_ & ~applied_, now);
            tick_at_ = earliest(tick_at_, state_ == CState::Recovering ? rec_since_ + k_recover_max : settle_at);
        } else if (state_ == CState::Recovering) {
            set_state(CState::Monitor, Why::Moved);
            tick_at_ = MonoTime::never();
            changed(now);
        } else {
            tick_at_ = settle_at;
        }
        return;
    }
    case CState::Aborted:
        abort_tick(now);
        return;
    default:
        return;
    }
}

// ABORTED: the plan is undone where it can be. The root's own record decides first (H8): if its COMMIT is durable the
// network follows that plan; if it is being written nothing is sent yet. Otherwise the local ABORT is made durable
// (the channel module repeats it while its record memory is busy, H7) and every required member is told; the
// coordinator is MONITOR again only when the root's own record no longer holds the plan.
void Coordinator::abort_tick(MonoTime now) {
    channel::Channel &ch = engine_.chan();
    if (ch.commit_started()) {
        if (ch.committed()) {
            ++stats_.commits;
            aborted_local_ = false;
            cursor_ = 0;
            set_state(CState::Committed, Why::None); // the record is the evidence, not the earlier verdict
            tick_at_ = now;
            changed(now);
        } else {
            tick_at_ = now + ms(20);
        }
        return;
    }
    if (!bound_ && required_ != 0) {
        if (engine_.ledger().ready()) {
            rebind();
        } else if (now < abort_since_ + k_abort_ledger_wait) {
            tick_at_ = now + ms(500);
            return;
        }
    }
    channel::PlanRec rec;
    rec.plan = plan_;
    rec.phase = channel::Phase::Abort;
    if (!aborted_local_) {
        aborted_local_ = ch.local_plan(rec, now) == Status::Ok;
    }
    send_round(channel::Phase::Abort, required_, now);
    if (cursor_ == 0 && aborted_local_) { // one full round of ABORT went out
        if (ch.unsettled()) {              // ... but the root's own record still holds the plan (or is being written)
            tick_at_ = now + ms(100);
            return;
        }
        aborted_local_ = false;
        set_state(CState::Monitor, why_);
        tick_at_ = MonoTime::never();
        changed(now);
    }
}

void Coordinator::finish_settle(MonoTime now) {
    changes_[n_changes_++ % 4] = now.to_ms() / 1000;
    cool_until_ = now + ms(gen::defaults::channel::cooldown_ms);
    cursor_ = 0;
    if ((required_ & ~applied_) == 0) {
        set_state(CState::Monitor, Why::Moved);
        tick_at_ = MonoTime::never();
    } else { // some never confirmed: they follow when they find the mesh again (never undone from here)
        set_state(CState::Recovering, Why::None);
        rec_since_ = now;
        tick_at_ = now;
    }
    changed(now);
}

void Coordinator::on_local_switch(MonoTime now) {
    self_ev_ = 3;
    if (state_ == CState::Committed || state_ == CState::Preparing) {
        rollback_to_ = plan_.old_ch;
        switched_at_ = now;
        cursor_ = 0;
        set_state(CState::Switching, Why::None);
        tick_at_ = now;
        changed(now);
    }
}

// A receipt of the root itself (`self`) or of the member at `addr`.
void Coordinator::apply(bool self, uint16_t addr, const DeviceId &peer, const channel::Receipt &r, MonoTime now) {
    Sha256Digest h;
    if (state_ == CState::Monitor || state_ == CState::Survey || r.id != plan_.id || channel::plan_hash(plan_, h) != Status::Ok ||
        h != r.hash || (!self && ((required_ & bit(addr)) == 0 || !is_participant(addr, peer)))) {
        return;
    }
    const uint64_t b = self ? 0 : bit(addr);
    if (r.evidence == channel::Evidence::Refused) {
        last_refusal_ = static_cast<Status>(r.reason);
        if (state_ == CState::Preparing && hard_refusal(last_refusal_)) {
            abort_plan(last_refusal_ == Status::TimeUncertain ? Why::TimeUncertain : Why::Refused, now);
        }
        return;
    }
    const auto ev = static_cast<unsigned>(r.evidence);
    self_ev_ = self ? std::max(self_ev_, static_cast<uint8_t>(ev)) : self_ev_;
    ready_ |= ev >= 1 ? b : 0;
    stored_ |= ev >= 2 ? b : 0;
    applied_ |= ev >= 3 ? b : 0;
    if (self || (state_ == CState::Preparing && (required_ & ~ready_) == 0) ||
        (state_ == CState::Recovering && (required_ & ~applied_) == 0)) {
        tick_at_ = now; // that was the last one (or our own: the local commit can go on)
    }
}

void Coordinator::on_local_receipt(const channel::Receipt &r, MonoTime now) { apply(true, 0, DeviceId{}, r, now); }

// ---- records ---------------------------------------------------------------------------------------------
void Coordinator::on_record(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now) {
    uint16_t addr = 0;
    if (!member_of(peer, addr)) {
        return; // only an admitted member with an end session is heard
    }
    channel::Receipt rc;
    channel::TimeReq tq;
    channel::State st;
    channel::SurveyResult sr;
    channel::Degraded dg;
    switch (channel::op_of(body)) {
    case channel::Op::Receipt:
        if (decode(body, rc) == Status::Ok) {
            apply(false, addr, peer, rc, now);
        }
        break;
    case channel::Op::TimeReq:
        if (decode(body, tq) == Status::Ok && tq.term == engine_.identity().member().root_term) {
            channel::TimeResp r; // stamped on arrival and at sending: the queueing after this is the return path
            r.nonce = tq.nonce;
            r.term = tq.term;
            r.t1_us = tq.t1_us;
            r.t2_us = r.t3_us = now.us;
            std::array<uint8_t, channel::k_max_record> out{};
            std::size_t len = 0;
            if (encode(r, MutByteView{out}, len) == Status::Ok) {
                (void)engine_.delivery().send_control(peer, reply, ByteView{out.data(), len}, now);
            }
        }
        break;
    case channel::Op::State: {
        // A member that (re)attached tells where it is; one behind the last applied plan is brought up to date with
        // that plan alone (it never replays the ones in between, docs/20 §9).
        // The plan is the channel record's last applied one, not the coordinator's memory: after a restart the
        // coordinator holds none, and a deferred sleeper still has to learn the epoch (FIX10-D5).
        const channel::Plan &last = engine_.chan().plan();
        channel::PlanRec rec;
        rec.phase = channel::Phase::Commit;
        rec.plan = last;
        std::array<uint8_t, channel::k_max_record> out{};
        std::size_t len = 0;
        if (decode(body, st) == Status::Ok && last.epoch.value() != 0 && st.epoch < last.epoch &&
            last.epoch == engine_.chan().epoch() && state_ != CState::Preparing && encode(rec, MutByteView{out}, len) == Status::Ok) {
            (void)engine_.delivery().send_control(peer, reply, ByteView{out.data(), len}, now);
        }
        break;
    }
    case channel::Op::SurveyResult:
        if (decode(body, sr) == Status::Ok) {
            on_survey_result(addr, sr, now);
        }
        break;
    case channel::Op::Degraded:
        if (decode(body, dg) == Status::Ok) {
            ++stats_.degraded;
            note_degraded(addr, now);
        }
        break;
    default:
        break;
    }
}

// Two independent links (neither ends at the other's node) reporting sustained RF loss make a channel problem more
// likely than a route problem. One is the route module's business (C02): it repairs, the channel stays.
void Coordinator::note_degraded(uint16_t addr, MonoTime now) {
    const auto t = static_cast<uint32_t>(now.to_ms() / 1000);
    const uint32_t window = static_cast<uint32_t>(gen::defaults::channel::degradation_window_ms / 1000);
    auto fresh = [&](const Deg &d) { return d.addr != 0 && t - d.at_s <= window; };
    Deg *slot = std::find_if(deg_.begin(), deg_.end(), [&](const Deg &d) { return d.addr == addr; });
    if (slot == deg_.end()) {
        slot = std::find_if(deg_.begin(), deg_.end(), [&](const Deg &d) { return !fresh(d); });
    }
    if (slot == deg_.end()) {
        slot = std::min_element(deg_.begin(), deg_.end(), [](const Deg &a, const Deg &b) { return a.at_s < b.at_s; });
    }
    *slot = Deg{addr, t};
    bool independent = false;
    for (const Deg &a : deg_) {
        for (const Deg &b : deg_) {
            ShortAddr pa, pb;
            if (&a != &b && fresh(a) && fresh(b)) {
                (void)engine_.routes().topology().parent_of(ShortAddr{a.addr}, pa);
                (void)engine_.routes().topology().parent_of(ShortAddr{b.addr}, pb);
                independent = independent || (pa.value() != b.addr && pb.value() != a.addr);
            }
        }
    }
    if (!independent) {
        why_ = state_ == CState::Monitor && (why_ == Why::None || why_ == Why::SingleLink) ? Why::SingleLink : why_;
    } else if (may_start(false, now)) {
        start_survey(now);
    }
}

// ---- survey ----------------------------------------------------------------------------------------------
// Pairs are (child, parent) links of the approved tree. A visit takes both ends off the home channel for a moment,
// so it is allowed only when nobody else depends on them: the child is a leaf and its parent has no other child, or
// the operator granted the maintenance gap (docs/05 §4). Otherwise the survey is deferred with that reason and
// nothing leaves its channel (C11).
void Coordinator::start_survey(MonoTime now) {
    std::array<Pair, 64> links{};
    unsigned n = 0, eligible = 0;
    for (uint16_t a = k_first; a < k_end; ++a) {
        ShortAddr par;
        if (engine_.routes().topology().is_admitted(ShortAddr{a}) && attached(a, now) &&
            engine_.routes().topology().parent_of(ShortAddr{a}, par) == Status::Ok) {
            links[n++] = Pair{a, par.value()};
        }
    }
    std::array<bool, 64> ok{};
    for (unsigned i = 0; i < n; ++i) {
        ok[i] = gap_ || (children_of(links[i].child, now) == 0 && children_of(links[i].parent, now) == 1);
        eligible += ok[i];
    }
    if (n == 0 || eligible < std::min(2U, n)) { // "at least two places, all of them in a small network" (docs/05 §3)
        set_state(CState::Monitor, n == 0 ? Why::NoMembers : Why::GapNeeded);
        cool_until_ = now + k_retained_cooldown;
        return;
    }
    n_pairs_ = 0;
    const unsigned want = std::min<unsigned>(eligible, channel::k_max_pairs);
    for (unsigned i = 0, seen = 0; i < n && n_pairs_ < want; ++i) {
        if (ok[i] && seen++ * want / eligible == n_pairs_) { // spread over the eligible links
            pairs_[n_pairs_++] = links[i];
        }
    }
    n_cands_ = 0;
    const uint8_t cur = engine_.chan().current();
    for (unsigned k = 1; k <= 13 && n_cands_ < channel::k_max_cands; ++k) {
        const auto c = static_cast<uint8_t>(((cur - 1 + k) % 13) + 1);
        if (((engine_.config().rf.allowed_channels_mask >> c) & 1U) != 0 && c != cur) {
            cand_ch_[n_cands_++] = c;
        }
    }
    if (n_cands_ == 0) {
        set_state(CState::Monitor, Why::NoCandidates);
        return;
    }
    res_ = {};
    visit_ = vs_tries_ = pass_ = 0;
    vs_ = Vs::Idle;
    vs_at_ = now;
    survey_end_ = now + k_survey_max;
    survey_reason_ = Status::Ok;
    ++stats_.surveys;
    set_state(CState::Survey, Why::None);
}

// One side of the current visit: LISTEN to the parent (armed first), PROBE to the child (its answer is the sample).
void Coordinator::send_survey(channel::Side role, MonoTime now) {
    const unsigned per = 1U + n_cands_, p = visit_ / per, ci = visit_ % per;
    const bool listen = role == channel::Side::Listen;
    channel::Survey s;
    s.sid = sid_;
    s.role = role;
    s.channel = ci == 0 ? engine_.chan().current() : cand_ch_[ci - 1];
    s.peer = listen ? pairs_[p].child : pairs_[p].parent;
    s.start_root_ms = vs_start_ms_;
    s.visit_ms = static_cast<uint16_t>(gen::defaults::channel::survey_visit_ms);
    s.tol_ms = vs_tries_ <= 1 ? k_tol_ms : k_tol_wide_ms;
    s.probes = k_probes;
    // (set first: the root's own listener answers from inside the call) an ack is due in 1.5 s, a result 4 s after the window began
    vs_at_ = listen ? now + ms(1500) : std::max(MonoTime{(vs_start_ms_ + 4000U) * 1000U}, now + Duration::from_s(2));
    const uint16_t to = listen ? pairs_[p].parent : pairs_[p].child;
    if (to == engine_.identity().member().address.value()) {
        (void)engine_.chan().local_survey(s, now);
    } else {
        (void)send_to(to, s, now);
    }
}

void Coordinator::next_visit(MonoTime now) {
    const unsigned per = 1U + n_cands_, total = n_pairs_ * per;
    auto missing = [&](unsigned v) { return !channel::usable(res_[v / per][v % per]); };
    do {
        ++visit_;
    } while (visit_ < total && pass_ > 0 && !missing(visit_));
    if (visit_ >= total && pass_ == 0) { // a visit that gave nothing (busy relay, wide clock bound) gets one more chance
        pass_ = 1;
        for (visit_ = 0; visit_ < total && !missing(visit_);) {
            ++visit_;
        }
    }
    vs_tries_ = 0;
    vs_ = Vs::Idle;
    vs_at_ = now;
}

// The same visit again with a new window (a late ack, a clock bound that had widened, a lost answer), bounded.
void Coordinator::retry_visit(MonoTime now, Duration delay) {
    if (vs_tries_ >= k_visit_tries) {
        next_visit(now);
        return;
    }
    vs_ = Vs::Idle;
    vs_at_ = now + delay;
}

void Coordinator::end_survey(MonoTime now) {
    (void)now;
    vs_ = Vs::Idle;
    vs_at_ = MonoTime::never();
}

void Coordinator::survey_tick(MonoTime now) {
    if (now >= survey_end_) {
        end_survey(now);
        set_state(CState::Monitor, Why::SurveyFailed);
        cool_until_ = now + k_retained_cooldown;
        return;
    }
    const unsigned per = 1U + n_cands_, total = n_pairs_ * per;
    switch (vs_) {
    case Vs::Idle: {
        if (visit_ < total) {
            ++sid_;
            sid_ += sid_ == 0;
            vs_start_ms_ = now.to_ms() + k_lead_ms;
            ++vs_tries_;
            ++stats_.visits;
            vs_ = visit_ % per == 0 ? Vs::Probe : Vs::Listen; // the home baseline needs no listener
            send_survey(vs_ == Vs::Probe ? channel::Side::Probe : channel::Side::Listen, now);
            return;
        }
        end_survey(now);
        const channel::Choice c = channel::decide(res_.data(), n_pairs_, n_cands_, gen::defaults::channel::minimum_improvement_percent);
        cool_until_ = now + k_retained_cooldown;
        if (c.verdict == channel::Verdict::Move && begin_plan(cand_ch_[c.index - 1], now) == Status::Ok) {
            why_ = Why::None;
        } else if (c.verdict == channel::Verdict::Move) {
            set_state(CState::Monitor, why_ == Why::None ? Why::Refused : why_);
        } else {
            set_state(CState::Monitor, c.verdict == channel::Verdict::Worse   ? Why::RetainedWorse
                                       : c.verdict == channel::Verdict::Small ? Why::RetainedSmall
                                       : survey_reason_ == Status::TimeUncertain ? Why::TimeUncertain
                                                                                 : Why::RetainedNoData);
        }
        return;
    }
    case Vs::Listen: // no ack in time
        retry_visit(now, Duration::from_ms(0));
        return;
    case Vs::Probe: // no answer in time: ask again under the same window (the node sends its result again)
        if (vs_tries_ >= k_visit_tries) {
            next_visit(now);
        } else {
            ++vs_tries_;
            send_survey(channel::Side::Probe, now);
        }
        return;
    case Vs::Gap:
        next_visit(now);
        return;
    }
}

void Coordinator::on_survey_result(uint16_t addr, const channel::SurveyResult &r, MonoTime now) {
    if (state_ != CState::Survey || r.sid != sid_ || (vs_ != Vs::Listen && vs_ != Vs::Probe)) {
        return;
    }
    const unsigned per = 1U + n_cands_, p = visit_ / per, ci = visit_ % per;
    const bool listen = r.role == channel::Side::Listen;
    if (addr != (listen ? pairs_[p].parent : pairs_[p].child) || (listen != (vs_ == Vs::Listen))) {
        return;
    }
    if (r.status != 0) {
        survey_reason_ = static_cast<Status>(r.status);
        const bool again = r.status == static_cast<uint8_t>(Status::TimeUncertain) ||
                           r.status == static_cast<uint8_t>(Status::Expired) || r.status == static_cast<uint8_t>(Status::Busy);
        again ? retry_visit(now, Duration::from_s(8)) : next_visit(now); // the node measures its clock now; a busy one is asked again
    } else if (listen) {
        if (now.to_ms() + k_min_arm_ms > vs_start_ms_) { // the ack came too late for the visitor to be armed in time
            retry_visit(now, Duration::from_s(2));
        } else {
            vs_ = Vs::Probe;
            send_survey(channel::Side::Probe, now);
        }
    } else {
        res_[p][ci] = channel::Sample{r.ok, r.fail, r.service_ms};
        if (ci == 0) {
            next_visit(now);
        } else {
            vs_ = Vs::Gap;
            vs_at_ = now + k_visit_gap;
        }
    }
}

void Coordinator::on_local_survey(const channel::SurveyResult &r, MonoTime now) {
    on_survey_result(engine_.identity().member().address.value(), r, now);
}

// ---- persistence / lifecycle -----------------------------------------------------------------------------
void Coordinator::save(Writer &w) const {
    w.u8(frozen_ ? 1 : 0);
    w.u64be(policy_rev_);
    w.u8(static_cast<uint8_t>(state_));
    w.u8(rollback_to_);
    w.u64be(required_);
    channel::put_plan(w, plan_);
    // Pacing debt (FIX3-D8): the age of each change of the last day and the cooldown still to run, as of this write.
    // A restart cannot know how long the power was off, so it counts none of that time (it never refills a bucket).
    const int64_t t = engine_.step_time().to_ms() / 1000;
    uint8_t n = 0;
    std::array<uint32_t, 4> age{};
    for (uint8_t i = 0; i < std::min<uint8_t>(n_changes_, 4); ++i) {
        if (t - changes_[i] < 86400) {
            age[n++] = static_cast<uint32_t>(std::max<int64_t>(t - changes_[i], 0));
        }
    }
    w.u8(n);
    for (uint8_t i = 0; i < n; ++i) {
        w.u32be(age[i]);
    }
    const int64_t cool = (cool_until_ - engine_.step_time()).to_ms();
    w.u32be(cool > 0 ? static_cast<uint32_t>(std::min<int64_t>(cool, 0xFFFFFFFFLL)) : 0U);
}

void Coordinator::restore(Reader &r, const channel::Plan *held, bool committed) {
    const bool frozen = r.u8() != 0;
    const uint64_t rev = r.u64be();
    const auto st = static_cast<CState>(r.u8() & 7U);
    const uint8_t rb = r.u8();
    const uint64_t req = r.u64be();
    const channel::Plan p = channel::get_plan(r);
    const bool ok = r.ok() && rev <= k_u63_max;
    // Pacing debt; a record without it (older format) is read as a cooldown that has just started.
    const uint8_t n = r.u8();
    std::array<uint32_t, 4> age{};
    for (uint8_t i = 0; i < std::min<uint8_t>(n, 4); ++i) {
        age[i] = r.u32be();
    }
    const uint32_t cool = r.u32be();
    if (ok) {
        if (r.ok() && n <= 4) {
            restored_age_ = age;
            restored_n_ = n;
            restored_cool_ms_ = cool;
        } else {
            restored_n_ = 0;
            restored_cool_ms_ = static_cast<uint32_t>(gen::defaults::channel::cooldown_ms);
        }
        restored_ = true;
    }
    if (ok) {
        frozen_ = frozen;
        policy_rev_ = rev;
        rollback_to_ = rb <= 13 ? rb : 0;
    }
    // A plan that was COMMITTED when the power went is followed to its end, never rolled back (docs/05 §7). The channel
    // record is the evidence: the coordinator's own state may have been saved a moment earlier.
    if (held != nullptr && committed) {
        state_ = CState::Recovering;
        plan_ = *held;
        required_ = ok ? req : 0;
    } else if (held != nullptr || (ok && (st == CState::Preparing || st == CState::Aborted) && channel::valid_plan(p))) {
        // FIX10-D1: PREPARED (or PREPARING with the root's own PREPARE not durable, or an ABORT not finished) when the
        // power went. Nobody will commit that plan: it is aborted now, as it would have been after its timeout - the
        // members that hold it are told, the root's own record is made IDLE.
        state_ = CState::Aborted;
        why_ = Why::PrepareTimeout;
        plan_ = held != nullptr ? *held : p;
        required_ = ok ? req : 0;
        ++stats_.aborts;
    } else if (ok && static_cast<uint8_t>(st) >= static_cast<uint8_t>(CState::Committed) && st != CState::Aborted) {
        state_ = CState::Recovering;
        plan_ = p;
        required_ = req;
    }
}

void Coordinator::on_loaded(MonoTime now) {
    if (restored_) { // the pacing debt of the previous run, with the elapsed time counted as zero
        restored_ = false;
        n_changes_ = restored_n_;
        for (uint8_t i = 0; i < restored_n_; ++i) {
            changes_[i] = now.to_ms() / 1000 - static_cast<int64_t>(restored_age_[i]);
        }
        cool_until_ = now + ms(restored_cool_ms_);
    }
    if (state_ == CState::Recovering || state_ == CState::Aborted) {
        cursor_ = 0;
        rec_since_ = abort_since_ = now;
        tick_at_ = now + Duration::from_s(5);
    }
}

void Coordinator::stop() {
    state_ = CState::Monitor;
    why_ = Why::None;
    vs_ = Vs::Idle;
    tick_at_ = vs_at_ = MonoTime::never();
    required_ = ready_ = stored_ = applied_ = deferred_ = 0;
    bound_ = false;
    self_ev_ = cursor_ = n_pairs_ = 0;
    plan_ = channel::Plan{};
    deg_ = {};
    aborted_local_ = false;
    if (freeze_op_ != 0) { // FIX12-D5: its record write is not known to have landed: INDETERMINATE (the next start reads the record)
        engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(Status::RecoveryRequired), freeze_op_, nullptr);
        freeze_op_ = 0;
    }
    rec_since_ = abort_since_ = MonoTime::never();
}

void Coordinator::on_timer(MonoTime now) {
    if (!engine_.chan().loaded()) {
        return;
    }
    if (state_ == CState::Survey && now >= vs_at_) {
        survey_tick(now);
    } else if (state_ != CState::Monitor && state_ != CState::Survey && now >= tick_at_) {
        plan_tick(now);
    }
}

MonoTime Coordinator::deadline() const {
    return state_ == CState::Survey ? vs_at_ : (state_ == CState::Monitor ? MonoTime::never() : tick_at_);
}

Coordinator::View Coordinator::view() const {
    View v;
    v.state = state_;
    v.why = why_;
    v.current = engine_.chan().loaded() && engine_.chan().current() != 0 ? engine_.chan().current() : engine_.channel();
    const bool planned = state_ == CState::Committed || state_ == CState::Switching || state_ == CState::Settling ||
                         state_ == CState::Recovering;
    v.epoch = (planned ? std::max(engine_.chan().epoch(), plan_.epoch) : engine_.chan().epoch()).value();
    v.frozen = frozen_;
    v.policy_revision = policy_rev_;
    v.plan_id = plan_.id.bytes;
    const MonoTime t = engine_.step_time();
    v.cooldown_left_ms = t < cool_until_ ? static_cast<uint32_t>(std::min<int64_t>((cool_until_ - t).to_ms(), 0xFFFFFFFFLL)) : 0U;
    for (uint8_t i = 0; i < std::min<uint8_t>(n_changes_, 4); ++i) {
        v.changes_24h = static_cast<uint8_t>(v.changes_24h + (t.to_ms() / 1000 - changes_[i] < 86400 ? 1U : 0U));
    }
    if (plan_.epoch.value() != 0 && state_ != CState::Survey) { // the current plan, or the last one
        v.required = required_;
        v.ready = ready_;
        v.stored = stored_;
        v.applied = applied_;
        v.deferred = deferred_;
        // Never confirmed STORED after the switch: unreachable. Stored but not yet applied is neither.
        v.unreachable = state_ == CState::Switching || state_ == CState::Settling || state_ == CState::Recovering ? required_ & ~stored_ : 0;
    }
    return v;
}

} // namespace lm::root
