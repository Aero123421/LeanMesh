#include "core/channel/channel.hpp"

#include <algorithm>

#include "core/engine.hpp"
#include "core/link/seal.hpp"
#include "core/route/mesh_wire.hpp"

namespace lm::channel {
namespace {

constexpr uint8_t k_rec_version = 1;
constexpr Duration k_retry = Duration::from_ms(50);

Duration ms(uint64_t v) { return Duration::from_ms(static_cast<int64_t>(v)); }
bool valid_channel(uint8_t c) { return c >= 1 && c <= 13; }

} // namespace

bool Channel::is_root() const { return k_root_capable && engine_.config().role == lm::Role::Root; }
RootTerm Channel::term() const { return engine_.identity().member().root_term; }
uint16_t Channel::allowed_mask() const { return engine_.config().rf.allowed_channels_mask; }

uint16_t Channel::jitter(uint16_t modulus) {
    std::array<uint8_t, 2> r{};
    engine_.random(MutByteView{r});
    return modulus == 0 ? 0 : static_cast<uint16_t>((uint32_t{r[0]} << 8U | r[1]) % modulus);
}

MonoTime Channel::reach(uint64_t root_ms, MonoTime now) {
    const RootTimeBound b = engine_.delivery().root_time(now);
    if (!b.valid) {
        return MonoTime::never();
    }
    return root_ms <= b.earliest_ms ? now : now + ms(root_ms - b.earliest_ms);
}

uint64_t Channel::clock_width_ms(MonoTime now) {
    const RootTimeBound b = engine_.delivery().root_time(now);
    return b.valid && b.term == term() ? b.latest_ms - b.earliest_ms : UINT64_MAX;
}

Status Channel::to_root(ByteView rec, MonoTime now) {
    delivery::PathSpec path;
    if (!engine_.mesh().route_to_root(path, now)) {
        return Status::NoRoute;
    }
    return engine_.delivery().send_control(engine_.identity().delegation().root, path, rec, now);
}

void Channel::notify(uint32_t detail) { engine_.raise(LM_EVENT_CHANNEL, static_cast<uint32_t>(mode()) << 8U | detail); }

Mode Channel::mode() const {
    if (sc_ == Sc::Dwell || sc_ == Sc::Backoff) {
        return Mode::Searching;
    }
    return phase_ == Ph::Committed ? Mode::Committed : (phase_ == Ph::Prepared ? Mode::Prepared : Mode::Normal);
}

Status Channel::set_radio(uint8_t channel) { return engine_.channel() == channel ? Status::Ok : engine_.set_channel(channel); }

// ---- persistence ------------------------------------------------------------------------------------
// The record: version | phase | current channel | epoch | plan body (always present) | root extras.

void Channel::on_identity_ready(MonoTime now) {
    if (!enabled_ || job_ != Job::None) {
        return;
    }
    if (begin_job(Job::Load, nullptr, After::None, now) != Status::Ok) {
        retry_at_ = now + k_retry;
    }
}

Status Channel::begin_job(Job kind, const Snap *snap, After after, MonoTime now) {
    (void)now;
    if (job_ != Job::None || cancelled_) {
        return Status::Busy;
    }
    rec_ = engine_.identity().lend_record();
    if (rec_ == nullptr) {
        return Status::Busy;
    }
    rec_->id = store::rec::channel_plan;
    rec_->op = kind == Job::Load ? store::RecordJob::Op::Load : store::RecordJob::Op::Commit;
    if (kind == Job::Persist) {
        Writer w{MutByteView{rec_->payload}};
        w.u8(k_rec_version);
        w.u8(static_cast<uint8_t>(snap->phase));
        w.u8(snap->cur);
        w.u32be(snap->epoch.value());
        put_plan(w, snap->plan);
        if (is_root()) {
            engine_.coordinator().save(w);
        }
        if (!w.ok()) {
            engine_.identity().return_record();
            rec_ = nullptr;
            return Status::NoCapacity;
        }
        rec_->state = static_cast<uint8_t>(snap->phase);
        rec_->payload_len = static_cast<uint32_t>(w.size());
    }
    job_slot_ = Handle{0, ++job_gen_};
    const Status st = engine_.submit_job(JobOwner::Channel, job_slot_, JobClass::Flash, &store::record_job, rec_);
    if (st != Status::Ok) {
        engine_.identity().return_record();
        rec_ = nullptr;
        return st;
    }
    job_ = kind;
    after_ = after;
    return Status::Ok;
}

void Channel::kick(MonoTime now) {
    if (!dirty_ || !loaded_ || job_ != Job::None) {
        return;
    }
    Snap s;
    s.phase = phase_;
    s.cur = cur_;
    s.epoch = epoch_;
    s.plan = plan_;
    if (begin_job(Job::Persist, &s, After::None, now) == Status::Ok) {
        dirty_ = false;
    } else {
        retry_at_ = now + k_retry;
    }
}

void Channel::on_job_done(Handle slot, Status s, MonoTime now) {
    const Job j = job_;
    job_ = Job::None;
    if (cancelled_) { // stop() kept the borrowed memory reserved for this job: the late result is discarded
        cancelled_ = false;
        engine_.identity().return_record();
        rec_ = nullptr;
        return;
    }
    if (j == Job::None || slot != job_slot_) {
        return;
    }
    if (j == Job::Load) {
        loaded_ok(s, now);
    } else {
        persisted(s, now);
    }
}

// Parses the record memory into the live state (used by load and by a successful persist).
static bool parse_record(const store::RecordJob &r, uint8_t &phase, uint8_t &cur, ChannelEpoch &epoch, Plan &plan,
                         Reader &rd) {
    const uint8_t ver = rd.u8();
    phase = rd.u8();
    cur = rd.u8();
    epoch = ChannelEpoch{rd.u32be()};
    plan = get_plan(rd);
    (void)r;
    return rd.ok() && ver == k_rec_version && phase <= 2 && valid_channel(cur) && (phase == 0 || valid_plan(plan));
}

void Channel::loaded_ok(Status s, MonoTime now) {
    uint8_t phase = 0, cur = 0;
    ChannelEpoch epoch;
    Plan plan;
    Reader rd{ByteView{rec_->payload.data(), s == Status::Ok ? rec_->payload_len : 0}};
    if (s == Status::Ok && parse_record(*rec_, phase, cur, epoch, plan, rd)) {
        phase_ = static_cast<Ph>(phase);
        cur_ = cur;
        epoch_ = epoch;
        plan_ = plan;
        if (is_root()) {
            engine_.coordinator().restore(rd, phase_ == Ph::Committed ? &plan_ : nullptr);
        }
    } else if (s == Status::NotFound) { // never planned: the deployment channel is the current one
        cur_ = engine_.channel();
    } else { // unreadable or quarantined: no guessing, no plan is accepted (docs/12 §2)
        faulted_ = true;
        cur_ = engine_.channel();
        engine_.emit_event(LM_EVENT_FAULT, static_cast<uint32_t>(s == Status::Ok ? Status::RecoveryRequired : s), 0, nullptr);
    }
    engine_.identity().return_record();
    rec_ = nullptr;
    loaded_ = true;
    if (phase_ == Ph::Committed) {
        apply_target(now); // a committed plan is followed even when nobody knows the schedule any more
    } else {
        (void)set_radio(cur_); // PREPARED, or nothing: the old channel
    }
    time_at_ = now; // the root anchors its own clock, a member waits for a path (the mesh arms the search)
    if (is_root()) {
        engine_.coordinator().on_loaded(now);
    }
    kick(now);
}

void Channel::persisted(Status s, MonoTime now) {
    const After a = after_;
    after_ = After::None;
    if (s != Status::Ok) {
        engine_.identity().return_record();
        rec_ = nullptr;
        ++stats_.refused;
        // Nothing was stored, so no receipt claims it: the root asks again (and the plan times out there).
        dirty_ = a == After::None; // a failed state write of our own is tried again
        retry_at_ = now + Duration::from_s(1);
        return;
    }
    uint8_t phase = 0, cur = 0;
    ChannelEpoch epoch;
    Plan plan;
    Reader rd{ByteView{rec_->payload.data(), rec_->payload_len}};
    if (parse_record(*rec_, phase, cur, epoch, plan, rd)) { // adopt what is now durable
        phase_ = static_cast<Ph>(phase);
        cur_ = cur;
        epoch_ = epoch;
        plan_ = plan;
    }
    engine_.identity().return_record();
    rec_ = nullptr;
    if (a == After::Prepared) {
        ++stats_.prepared;
        reply(plan_, Evidence::Prepared, Status::Ok, after_local_, now);
    } else if (a == After::Stored) {
        ++stats_.committed;
        reply(plan_, Evidence::Stored, Status::Ok, after_local_, now);
        arm_switch(now);
    } else if (a == After::Applied) {
        reply(plan_, Evidence::Applied, Status::Ok, after_local_, now);
    }
    notify(0);
    kick(now);
}

// ---- plan (participant) -----------------------------------------------------------------------------
void Channel::on_plan(const PlanRec &rec, bool local, MonoTime now) {
    after_local_ = local;
    switch (rec.phase) {
    case Phase::Prepare:
        prepare(rec.plan, local, now);
        break;
    case Phase::Commit:
        commit(rec.plan, local, now);
        break;
    case Phase::Abort:
        if (phase_ == Ph::Prepared && plan_.id == rec.plan.id) { // a committed plan cannot be aborted
            Snap s;
            s.cur = cur_;
            s.epoch = epoch_;
            (void)begin_job(Job::Persist, &s, After::None, now);
        }
        break;
    }
}

void Channel::reply(const Plan &p, Evidence ev, Status why, bool local, MonoTime now) {
    Receipt r;
    r.id = p.id;
    (void)plan_hash(p, r.hash);
    r.evidence = ev;
    r.reason = static_cast<uint32_t>(why);
    const uint64_t w = local ? 0 : clock_width_ms(now);
    r.clock_err_ms = w > 0xFFFFFFFFULL ? 0xFFFFFFFFU : static_cast<uint32_t>(w);
    if (local) {
        engine_.coordinator().on_local_receipt(r, now);
    } else {
        (void)send(r, now); // the root asks again until it has the receipt
    }
}

void Channel::prepare(const Plan &p, bool local, MonoTime now) {
    Status why = Status::Ok;
    RootTimeBound b;
    if (!local) {
        b = engine_.delivery().root_time(now);
    }
    if (faulted_) {
        why = Status::RecoveryRequired;
    } else if (p.term != term()) {
        why = Status::NetworkMismatch;
    } else if (phase_ == Ph::Prepared && plan_.id == p.id) {
        reply(p, Evidence::Prepared, Status::Ok, local, now); // the receipt again: it is durable already
        return;
    } else if (p.epoch <= epoch_) {
        why = Status::Conflict; // an old plan is never given life again
    } else if (phase_ == Ph::Committed) {
        why = Status::Busy; // a committed plan runs to completion first
    } else if (p.old_ch != engine_.channel()) { // the channel the radio is on (a straggler's stored one may be stale)
        why = Status::Conflict;
    } else if (((allowed_mask() >> p.new_ch) & 1U) == 0) {
        why = Status::RfProfileUnapproved;
    } else if (!local && (!b.valid || b.term != p.term || b.latest_ms - b.earliest_ms > p.max_err_ms)) {
        why = Status::TimeUncertain; // no READY without a clock bound inside the plan's tolerance (docs/05 §5)
    } else if (!local && p.switch_root_ms < b.latest_ms + 2U * p.max_err_ms + k_drain_ms + 500U + k_store_margin_ms) {
        why = Status::Expired;
    }
    if (why == Status::Ok) {
        Snap s;
        s.phase = Ph::Prepared;
        s.cur = cur_;
        s.epoch = epoch_;
        s.plan = p;
        why = begin_job(Job::Persist, &s, After::Prepared, now);
    }
    if (why != Status::Ok) {
        ++stats_.refused;
        reply(p, Evidence::Refused, why, local, now);
    }
}

void Channel::commit(const Plan &p, bool local, MonoTime now) {
    Status why = Status::Ok;
    const bool prepared = phase_ == Ph::Prepared && plan_.id == p.id;
    if (faulted_) {
        why = Status::RecoveryRequired;
    } else if (p.term != term()) {
        why = Status::NetworkMismatch;
    } else if (phase_ == Ph::Committed && plan_.id == p.id) {
        reply(p, Evidence::Stored, Status::Ok, local, now); // repeated COMMIT: stored already
        return;
    } else if (phase_ == Ph::Idle && epoch_ == p.epoch && cur_ == p.new_ch) {
        reply(p, Evidence::Applied, Status::Ok, local, now); // this plan is done here
        return;
    } else if (p.epoch <= epoch_ || phase_ == Ph::Committed) {
        why = Status::Conflict;
    } else if (!prepared && !(!local && engine_.channel() == p.new_ch)) {
        // Not prepared: only a node that reached the root on the target channel may catch up (it saw the
        // switch happen); anyone else has missed the PREPARE and must not be dragged along.
        why = Status::NotFound;
    }
    if (why == Status::Ok) {
        Snap s;
        s.phase = Ph::Committed;
        s.cur = cur_;
        s.epoch = epoch_;
        s.plan = p;
        why = begin_job(Job::Persist, &s, After::Stored, now);
    }
    if (why != Status::Ok) {
        ++stats_.refused;
        reply(p, Evidence::Refused, why, local, now);
    }
}

// Committed and durable: the guard, then the switch at the root time (never earlier than the estimate allows).
void Channel::arm_switch(MonoTime now) {
    sw_ = Sw::None;
    sw_at_ = MonoTime::never();
    sw_tries_ = 0;
    if (phase_ != Ph::Committed) {
        return;
    }
    const RootTimeBound b = engine_.delivery().root_time(now);
    if (!b.valid || b.term != plan_.term) {
        return; // waits for a clock: on_time_resp() arms it again
    }
    const uint64_t left = plan_.switch_root_ms > b.earliest_ms ? plan_.switch_root_ms - b.earliest_ms : 0;
    switch_at_ = now + ms(left);
    sw_ = Sw::Hold;
    sw_at_ = switch_at_ + Duration{-static_cast<int64_t>(ms(uint64_t{plan_.max_err_ms} + k_drain_ms).us)};
}

void Channel::switch_step(MonoTime now) {
    if (sw_ == Sw::None || now < sw_at_) {
        return;
    }
    if (sw_ == Sw::Hold) { // stop new DATA, let the frames in flight finish; control keeps going
        gap_end_ = switch_at_ + ms(uint64_t{plan_.max_err_ms} + 500); // guard = 2 * error + drain + 500 ms
        engine_.sched().hold_until(gap_end_);
        sw_ = Sw::Switch;
        sw_at_ = switch_at_;
    }
    if (sw_ == Sw::Switch && now >= switch_at_) {
        if (set_radio(plan_.new_ch) != Status::Ok) { // a failed readback is not a switch: STORED, not APPLIED
            sw_at_ = ++sw_tries_ >= 5 ? MonoTime::never() : now + Duration::from_s(1);
            sw_ = sw_tries_ >= 5 ? Sw::None : Sw::Switch;
            notify(1);
            return;
        }
        cur_ = plan_.new_ch;
        epoch_ = plan_.epoch;
        phase_ = Ph::Idle;
        ++stats_.switched;
        dirty_ = true;
        sw_ = Sw::Release;
        sw_at_ = gap_end_;
        notify(0);
        if (is_root()) {
            engine_.coordinator().on_local_switch(now);
        }
        kick(now);
        return;
    }
    if (sw_ == Sw::Release && now >= gap_end_) {
        sw_ = Sw::None;
        sw_at_ = MonoTime::never();
    }
}

// A committed plan found at boot, or a caught-up node: the target is the channel (no rollback by the node).
void Channel::apply_target(MonoTime now) {
    if (set_radio(plan_.new_ch) != Status::Ok) {
        faulted_ = true; // the radio refused the stored channel: say so, do not go back to the old one
        engine_.emit_event(LM_EVENT_FAULT, static_cast<uint32_t>(Status::RfProfileUnapproved), 0, nullptr);
        return;
    }
    cur_ = plan_.new_ch;
    epoch_ = plan_.epoch;
    phase_ = Ph::Idle;
    dirty_ = true;
    if (is_root()) {
        engine_.coordinator().on_local_switch(now);
    }
}

// ---- time ----------------------------------------------------------------------------------------------
void Channel::anchor_root(MonoTime now) {
    RootTimeBound b;
    b.term = term();
    b.earliest_ms = b.latest_ms = now.to_ms();
    b.valid = true;
    engine_.set_root_time(b, now);
}

void Channel::time_step(MonoTime now) {
    if (now < time_at_) {
        return;
    }
    if (is_root()) { // the root is the time base of its term
        anchor_root(now);
        time_at_ = now + k_time_refresh;
        return;
    }
    if (engine_.mesh().state() != route::Mesh::State::Ready) {
        time_at_ = MonoTime::never(); // on_ready() asks again
        return;
    }
    if (time_wait_ && time_tries_ < 8) {
        ++time_tries_;
    }
    TimeReq q;
    engine_.random(MutByteView{nonce_});
    q.nonce = nonce_;
    q.term = term();
    q.t1_us = now.us;
    if (send(q, now) == Status::Ok) {
        time_wait_ = true;
        t1_ = now;
        // No answer: 4 s, 8 s ... doubling, at most the refresh interval (docs/20: no fixed fast retry).
        const int64_t wait = std::min<int64_t>(int64_t{4} << std::min<uint8_t>(time_tries_, 5), 120);
        time_at_ = now + Duration::from_s(wait);
        State st;
        st.epoch = epoch_;
        st.channel = engine_.channel();
        state_sent_ = state_sent_ || send(st, now) == Status::Ok;
    } else {
        time_at_ = now + Duration::from_s(2); // no path or session for a moment: local, not a failure
    }
}

void Channel::on_time_resp(const TimeResp &r, MonoTime now) {
    if (!time_wait_ || r.nonce != nonce_ || r.term != term() || r.t1_us != t1_.us) {
        return;
    }
    // The answer was produced at root time t3; it travelled back for at most (rtt - root processing).
    const uint64_t rtt = now.us - t1_.us;
    const uint64_t proc = r.t3_us - r.t2_us;
    const uint64_t spread = rtt > proc ? rtt - proc : 0;
    RootTimeBound b;
    b.term = r.term;
    b.earliest_ms = r.t3_us / 1000U;
    b.latest_ms = (r.t3_us + spread + 999U) / 1000U;
    b.valid = true;
    // Two valid intervals of the same term both contain the truth: keep their overlap (the narrowest RTT wins).
    // No overlap means the clock base changed (a restarted root): the new answer replaces the old one.
    const RootTimeBound old = engine_.delivery().root_time(now);
    if (old.valid && old.term == b.term && std::max(old.earliest_ms, b.earliest_ms) <= std::min(old.latest_ms, b.latest_ms)) {
        b.earliest_ms = std::max(old.earliest_ms, b.earliest_ms);
        b.latest_ms = std::min(old.latest_ms, b.latest_ms);
    }
    engine_.set_root_time(b, now);
    time_wait_ = false;
    time_tries_ = 0;
    time_at_ = now + k_time_refresh;
    ++stats_.time_updates;
    if (phase_ == Ph::Committed && sw_ == Sw::None) {
        arm_switch(now);
    }
}

// ---- mesh hooks ---------------------------------------------------------------------------------------
void Channel::on_ready(MonoTime now) {
    if (!enabled_ || !loaded_ || is_root()) {
        return;
    }
    sc_ = Sc::Idle;
    sc_at_ = MonoTime::never();
    sc_backoff_ = k_backoff_min;
    scan_tries_ = 0;
    state_sent_ = false;
    time_tries_ = 0;
    time_wait_ = false;
    time_at_ = now;
}

void Channel::on_lost(MonoTime now) {
    if (!enabled_ || !loaded_ || is_root() || sc_ != Sc::Idle) {
        return;
    }
    sc_ = Sc::Armed;
    sc_at_ = now + k_scan_after;
}

void Channel::on_link_sample(bool ok, MonoTime now) {
    if (!enabled_ || !loaded_ || is_root()) {
        return;
    }
    if (win_end_.is_never()) {
        win_end_ = now + ms(gen::defaults::channel::degradation_window_ms);
    }
    if (now >= win_end_) {
        // RF attempts only (BUSY, NO_MEM and planned gaps never reach this function). Loss > 10 % of >= 32.
        if (win_attempts_ >= gen::defaults::channel::minimum_samples && uint32_t{win_fails_} * 10U > win_attempts_) {
            Degraded d;
            d.attempts = win_attempts_;
            d.loss_q16 = static_cast<uint32_t>((uint64_t{win_fails_} << 16U) / win_attempts_);
            stats_.degraded_sent += send(d, now) == Status::Ok ? 1U : 0U;
        }
        win_attempts_ = win_fails_ = 0;
        win_end_ = now + ms(gen::defaults::channel::degradation_window_ms);
    }
    if (win_attempts_ != UINT16_MAX) {
        ++win_attempts_;
        win_fails_ = static_cast<uint16_t>(win_fails_ + (ok ? 0 : 1));
    }
}

// ---- recovery scan --------------------------------------------------------------------------------------
// Order: the stored channel, the pending target, then the rest of the allowed set (docs/05 §7, docs/20 §8).
unsigned Channel::scan_list(std::array<uint8_t, 14> &list) const {
    unsigned n = 0;
    auto add = [&](uint8_t c) {
        if (valid_channel(c) && ((allowed_mask() >> c) & 1U) != 0 && std::find(list.begin(), list.begin() + n, c) == list.begin() + n) {
            list[n++] = c;
        }
    };
    add(engine_.channel()); // where the radio is now (a parent may have answered here), then the stored channel
    add(cur_);
    if (phase_ != Ph::Idle) {
        add(plan_.new_ch);
    }
    for (uint8_t c = 1; c <= 13; ++c) {
        add(c);
    }
    return n;
}

void Channel::scan_end(MonoTime now) {
    (void)set_radio(cur_); // back to the stored channel between attempts
    const Duration b = sc_backoff_ + ms(jitter(static_cast<uint16_t>(std::min<int64_t>(sc_backoff_.to_ms() / 5, 12000))));
    sc_ = Sc::Backoff;
    sc_at_ = now + b;
    sc_backoff_ = sc_backoff_ + sc_backoff_ > k_backoff_max ? k_backoff_max : sc_backoff_ + sc_backoff_;
    if (scan_limit_ != 0 && scan_tries_ >= scan_limit_) { // battery episode budget used: isolated until the next wake
        sc_ = Sc::Idle;
        sc_at_ = MonoTime::never();
    }
}

void Channel::scan_step(MonoTime now) {
    if (sc_ == Sc::Idle || now < sc_at_) {
        return;
    }
    route::Mesh &mesh = engine_.mesh();
    if (mesh.state() == route::Mesh::State::Ready || mesh.state() == route::Mesh::State::Root) {
        sc_ = Sc::Idle;
        sc_at_ = MonoTime::never();
        return;
    }
    if (mesh.state() == route::Mesh::State::Attach && sc_ != Sc::Dwell) {
        sc_at_ = now + Duration::from_s(2); // a handshake with a parent found on this channel is under way: do not hop away
        return;
    }
    std::array<uint8_t, 14> list{};
    const unsigned n = scan_list(list);
    if (sc_ != Sc::Dwell) { // Armed or Backoff: a new attempt, but not while a switch or a visit is under way
        if (phase_ == Ph::Committed || sw_ != Sw::None || job_ != Job::None || sv_ != Sv::None || n == 0) {
            sc_at_ = now + Duration::from_s(1);
            return;
        }
        ++stats_.scans;
        ++scan_tries_;
        sc_ = Sc::Dwell;
        sc_index_ = 0;
        sc_lap_ = 0;
        dwell_open_ = false;
        notify(2);
    }
    if (dwell_open_) { // a dwell just ended
        dwell_open_ = false;
        if (mesh.heard_since(dwell_start_)) { // somebody answered on this channel: stay, the mesh attaches
            sc_ = Sc::Armed; // if it does not reach a parent within k_scan_after (the neighbour moved on), search again
            sc_at_ = now + k_scan_after;
            notify(3);
            return;
        }
        if (++sc_index_ >= n) { // one lap done
            sc_index_ = 0;
            if (++sc_lap_ >= k_scan_laps) {
                scan_end(now);
                return;
            }
        }
    }
    (void)set_radio(list[sc_index_ % n]);
    ++stats_.scan_dwells;
    dwell_start_ = now;
    dwell_open_ = true;
    mesh.hello_now(now); // ask for a parent on this channel (a neighbour answers with its beacon)
    sc_at_ = now + k_dwell;
}

// ---- survey (participant) ---------------------------------------------------------------------------------
void Channel::answer(const SurveyResult &r, bool local, MonoTime now) {
    if (local) {
        engine_.coordinator().on_local_survey(r, now);
    } else {
        (void)send(r, now);
    }
}

void Channel::on_survey(const Survey &s, bool local, MonoTime now) {
    SurveyResult res;
    res.sid = s.sid;
    res.role = s.role;
    if (s.sid == svq_.sid) { // a request we took already: the same answer again
        if (s.role == Side::Listen && sv_ != Sv::None) {
            answer(res, local, now);
        } else if (s.role == Side::Probe && sv_ == Sv::None && result_.sid == s.sid) {
            answer(result_, local, now);
        }
        return;
    }
    const bool visit = s.channel != engine_.channel(); // else a baseline probe on the home channel: no clock needed
    if (local) {
        anchor_root(now); // the root's own interval is exact
    }
    const RootTimeBound b = visit ? engine_.delivery().root_time(now) : RootTimeBound{};
    Status why = Status::Ok;
    MacAddr parent;
    if (sv_ != Sv::None || sw_ != Sw::None || phase_ == Ph::Committed || job_ != Job::None) {
        why = Status::Busy; // one visit at a time, and never inside a switch guard
    } else if (!enabled_ || faulted_ || (visit && ((allowed_mask() >> s.channel) & 1U) == 0)) {
        why = Status::RfProfileUnapproved;
    } else if (visit && (!b.valid || b.term != term() || b.latest_ms - b.earliest_ms > s.tol_ms)) {
        why = Status::TimeUncertain; // a 60 ms visit needs a clock bound of the order of the tolerance
        if (!time_wait_ && !is_root()) {
            time_at_ = now; // the bound has widened since the last answer: measure again, the root asks once more
        }
    } else if (visit && s.start_root_ms < b.latest_ms + 500) {
        why = Status::Expired;
    } else if (s.role == Side::Probe && (engine_.mesh().parent_addr().value() != s.peer || !engine_.mesh().parent_mac(parent))) {
        why = Status::NoRoute; // the tree moved since the root chose this pair
    }
    if (why != Status::Ok) {
        res.status = static_cast<uint8_t>(why);
        answer(res, local, now);
        return;
    }
    ++stats_.surveys;
    svq_ = s;
    sv_visit_ = visit;
    sv_home_ = engine_.channel();
    sv_ = Sv::Wait;
    probes_done_ = probes_ok_ = probes_fail_ = 0;
    probe_out_ = false;
    result_ = SurveyResult{};
    sv_at_ = visit ? reach(s.start_root_ms + (s.role == Side::Listen ? 0 : s.tol_ms) - 300, now) : now;
    if (s.role == Side::Listen) {
        answer(res, local, now); // armed: the root may now send the visitor
    }
}

// Wait -> Prep (guard: data held, no RF-loss samples) -> Away (on the candidate channel). The root time decides, never
// a timer of ours: the listener enters when the estimate says the window began, the visitor tol later; the listener
// leaves after the visitor's window plus the tolerances; the visitor stops by the earliest estimate.
void Channel::survey_step(MonoTime now) {
    if (sv_ == Sv::None || now < sv_at_) {
        return;
    }
    const bool listen = svq_.role == Side::Listen;
    const uint64_t enter = svq_.start_root_ms + (listen ? 0 : svq_.tol_ms);
    const uint64_t leave = svq_.start_root_ms + svq_.visit_ms + (listen ? 2U * svq_.tol_ms : svq_.tol_ms);
    if (sv_ == Sv::Wait) {
        if (sv_visit_) {
            gap_end_ = reach(leave + 300, now);
            engine_.sched().hold_until(gap_end_);
        }
        sv_ = Sv::Prep;
    }
    if (sv_ == Sv::Prep) {
        const MonoTime t = sv_visit_ ? reach(enter, now) : now;
        if (t > now) {
            sv_at_ = t;
            return;
        }
        if (sv_visit_ && set_radio(svq_.channel) != Status::Ok) {
            result_.status = static_cast<uint8_t>(Status::RfProfileUnapproved);
            survey_finish(now);
            return;
        }
        sv_ = Sv::Away;
    }
    if (!listen) {
        probe_next(now);
    } else if (reach(leave, now) > now) {
        sv_at_ = reach(leave, now);
    } else {
        survey_finish(now);
    }
}

void Channel::probe_next(MonoTime now) {
    if (probes_done_ >= svq_.probes || (sv_visit_ && reach(svq_.start_root_ms + svq_.tol_ms + svq_.visit_ms, now) <= now)) {
        survey_finish(now); // (a probe still in flight is ignored from here on)
        return;
    }
    if (probe_out_) {
        sv_at_ = now + Duration::from_ms(svq_.visit_ms);
        return;
    }
    MacAddr parent;
    route::Beacon b; // a beacon with no path: every mesh ignores it, the radio still acknowledges it
    b.term = term().value();
    std::array<uint8_t, wire::k_link_header_bytes + 11> frame{};
    std::size_t len = 0;
    if (!engine_.mesh().parent_mac(parent) ||
        route::encode_beacon(b, link::domain_hint_of(engine_.identity().delegation().domain), MutByteView{frame}, len) !=
            Status::Ok) {
        survey_finish(now);
        return;
    }
    probe_out_ = engine_.transmit(parent, ByteView{frame.data(), len}, k_tag_channel | probes_done_, now) == Status::Ok;
    probe_sent_ = now;
    // The outcome callback normally comes first; else the window backstop, or (radio occupied: not a lost probe) 2 ms.
    sv_at_ = now + Duration::from_ms(probe_out_ ? svq_.visit_ms : 2);
}

void Channel::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    if ((o.tag & 0xFFFF0000U) != k_tag_channel || !probe_out_) {
        return;
    }
    probe_out_ = false;
    if (o.result == port::TxResult::MacAcked) {
        probe_ms_[probes_ok_ % k_max_probes] = static_cast<uint8_t>(std::min<int64_t>((o.at - probe_sent_).us / 1000, 255));
        ++probes_ok_;
    } else if (o.result == port::TxResult::MacFailed) {
        ++probes_fail_;
    }
    ++probes_done_;
    probe_next(now);
}

// Back on the home channel. A visitor reports once (the root asks again if it heard nothing; the result stays here).
void Channel::survey_finish(MonoTime now) {
    (void)set_radio(sv_home_);
    probe_out_ = false;
    sv_ = Sv::None;
    sv_at_ = MonoTime::never();
    if (svq_.role == Side::Listen) {
        return;
    }
    result_.sid = svq_.sid;
    result_.role = Side::Probe;
    result_.ok = probes_ok_;
    result_.fail = probes_fail_;
    const uint8_t n = std::min<uint8_t>(probes_ok_, k_max_probes);
    std::sort(probe_ms_.begin(), probe_ms_.begin() + n);
    result_.service_ms = n == 0 ? 0 : probe_ms_[n / 2];
    (void)send(result_, now);
}

Status Channel::local_survey(const Survey &s, MonoTime now) {
    if (job_ != Job::None) {
        return Status::Busy;
    }
    on_survey(s, true, now);
    return Status::Ok;
}

Status Channel::local_plan(const PlanRec &rec, MonoTime now) {
    if (job_ != Job::None || !loaded_) {
        return Status::Busy;
    }
    on_plan(rec, true, now);
    return Status::Ok;
}

// ---- records / timers ----------------------------------------------------------------------------------
void Channel::on_record(const DeviceId &peer, const delivery::PathSpec &reply_path, ByteView body, MonoTime now) {
    if (!enabled_ || !loaded_ || body.empty()) {
        return;
    }
    if (is_root()) {
        engine_.coordinator().on_record(peer, reply_path, body, now);
        return;
    }
    if (peer != engine_.identity().delegation().root) {
        return; // only the root plans, measures and answers the time
    }
    PlanRec plan;
    TimeResp tr;
    Survey sv;
    switch (op_of(body)) {
    case Op::Plan:
        if (decode(body, plan) == Status::Ok && job_ == Job::None) { // busy: the root asks again
            on_plan(plan, false, now);
        }
        break;
    case Op::TimeResp:
        if (decode(body, tr) == Status::Ok) {
            on_time_resp(tr, now);
        }
        break;
    case Op::Survey:
        if (decode(body, sv) == Status::Ok) {
            on_survey(sv, false, now);
        }
        break;
    default:
        break;
    }
}

void Channel::on_timer(MonoTime now) {
    if (!enabled_) {
        return;
    }
    if (now >= retry_at_) {
        retry_at_ = MonoTime::never();
        if (!loaded_) {
            on_identity_ready(now);
        }
        kick(now);
    }
    if (!loaded_) {
        return;
    }
    time_step(now);
    switch_step(now);
    scan_step(now);
    survey_step(now);
}

MonoTime Channel::deadline() const {
    if (!enabled_) {
        return MonoTime::never();
    }
    MonoTime d = retry_at_;
    if (loaded_) {
        d = earliest(d, time_at_);
        d = earliest(d, sw_ != Sw::None ? sw_at_ : MonoTime::never());
        d = earliest(d, sc_ != Sc::Idle ? sc_at_ : MonoTime::never());
        d = earliest(d, sv_ != Sv::None ? sv_at_ : MonoTime::never());
    }
    return d;
}

void Channel::stop() {
    sw_ = Sw::None;
    sv_ = Sv::None;
    sc_ = Sc::Idle;
    after_ = After::None;
    dirty_ = false;
    time_at_ = sw_at_ = sc_at_ = sv_at_ = retry_at_ = win_end_ = MonoTime::never();
    time_wait_ = false;
    gap_end_ = MonoTime{};
    engine_.sched().hold_until(MonoTime{});
    phase_ = Ph::Idle;
    plan_ = Plan{};
    cur_ = 0;
    epoch_ = ChannelEpoch{};
    faulted_ = false;
    loaded_ = !enabled_;
    dwell_open_ = false;
    if (job_ != Job::None) {
        cancelled_ = true; // the worker may still write into the borrowed record memory (zombie rule)
    } else if (rec_ != nullptr) {
        engine_.identity().return_record();
        rec_ = nullptr;
    }
}

} // namespace lm::channel
