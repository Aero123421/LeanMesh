// Power: lifecycle, policy, episodes, budgets, the sleep ticket and the sleep/wake transitions.
// Poll/grant and the parent mailbox are in power_link.cpp, the root's view in power_root.cpp.
#include "core/power/power.hpp"

#include <algorithm>
#include <cstring>

#include "core/engine.hpp"
#include "gen/defaults.hpp"
#include "store/record.hpp"

namespace lm::power {
namespace {

constexpr Duration k_ticket_life = Duration::from_ms(gen::defaults::power_limits::sleep_ticket_ms);
constexpr Duration k_busy_retry = Duration::from_ms(50); // a window that cannot close yet looks again
constexpr Duration k_veto_retry = Duration::from_s(1);    // HIL-F7: a held-back sleep without a known next window
constexpr Duration k_lock_retry = Duration::from_ms(200); // a PM lock the port did not confirm is asked for again
constexpr uint64_t k_hour_ms = 3600000ULL;
constexpr uint64_t k_day_ms = 86400000ULL;
constexpr uint8_t k_retained_magic = 0xB1;
constexpr std::size_t k_retained_bytes = 1 + 3 * 8 + 2 + 1; // magic, three buckets, cursor, fail streak, channel cursor

// The buckets count microseconds (radio time) and micro-events (wakes): one place converts a policy value, so a
// millisecond quantity cannot be scaled as if it were seconds (FIX3-D1).
constexpr uint64_t us_of_ms(uint32_t ms) { return uint64_t{ms} * 1000U; }
constexpr uint64_t micro_of(uint32_t n) { return uint64_t{n} * 1000000U; }

// Leaky bucket: `used` drains at limit/window. dt is whole milliseconds so small steps carry no rounding loss.
void leak(uint64_t &used, uint64_t limit, uint64_t window_ms, uint64_t dt_ms) {
    const uint64_t dec = dt_ms >= window_ms ? used : limit * dt_ms / window_ms;
    used = used > dec ? used - dec : 0;
}

// Time until a bucket that holds `used` has room again (below `limit`): the wake of a WINDOWED node that
// searched without a parent is stretched by this instead of being denied.
uint64_t refill_ms(uint64_t used, uint64_t limit, uint64_t window_ms) {
    return used < limit || limit == 0 ? 0 : (used - limit + 1U) * window_ms / limit + 1U;
}

} // namespace

uint64_t Power::off_limit() const { return us_of_ms(policy_.offline_radio_ms_per_hour); }
uint64_t Power::ext_limit() const { return us_of_ms(policy_.extra_radio_ms_per_day); }
uint64_t Power::wake_limit() const { return micro_of(policy_.extra_wakes_per_day); }

// ---- lifecycle ------------------------------------------------------------------------------------
void Power::on_start(MonoTime now) {
    stop();
    port::Pm *pm = engine_.pm();
    const port::WakeInfo w = pm != nullptr ? pm->boot_info() : port::WakeInfo{};
    bud_at_ = now;
    load_retained(w);
    wake_reason_ = w.source == LM_WAKE_TIMER ? kTimer : (w.source == LM_WAKE_EXTERNAL ? kExternal : kColdBoot);
    ep_extra_ = w.source == LM_WAKE_EXTERNAL && w.cause == port::ResetCause::DeepWake;
    last_path_ = SessionPath::FreshEdhoc; // nothing of the previous run's security state exists any more
    acct_at_ = now;
    st_ = State::Running;
}

void Power::stop() {
    if ((lock_want_ != 0 || lock_have_ != 0) && engine_.pm() != nullptr) {
        lock_have_ = engine_.pm()->set_locks(0);
    }
    lock_want_ = 0;
    lock_retry_ = MonoTime::never();
    st_ = State::Running;
    deny_pending_ = false;
    deny_retry_ = MonoTime::never();
    loaded_ = prep_active_ = ep_extra_ = false; // policy_job_ stays: a running job still owns rec_ (zombie rule)
    ticket_ = Ticket{};
    poll_ = Poll{};
    window_end_ = next_window_ = ep_end_ = overrun_at_ = wake_at_ = held_window_at_ = MonoTime::never();
    search_next_ = MonoTime{};
    ep_over_ = auto_ = false;
    acct_at_ = MonoTime::never();
    children_ = {};
    policy_ = gen::power_policy::k_always_rx; // a stopped node keeps no policy in RAM: the record is loaded again
    if (policy_job_) {
        policy_job_ = false;
        zombie_ = true;
    }
}

// The policy record was read with the identity (no job, no contention for the record memory at boot). Unreadable or
// invalid: ALWAYS_RX defaults and a FAULT event - never a silent guess of a sleepy mode.
void Power::on_identity_ready(MonoTime now) {
    const member::LocalIdentity &id = engine_.identity();
    loaded_ = true;
    Policy p;
    const Status st = id.power_policy_status();
    if (st == Status::Ok && decode_policy(id.power_policy(), p) == Status::Ok && validate(p, engine_.config().role) == Status::Ok) {
        policy_ = p;
    } else if (st != Status::NotFound) {
        engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(st == Status::Ok ? Status::RecoveryRequired : st));
    }
    settle_boot_budgets();
    advance_budgets(now);
    if (ep_extra_ && sleepy_mode() && !boot_grant_) {
        // FIX6-D3: a retained external Deep Sleep wake is an unplanned wake like wake() admits: the same quota, charged
        // once. (A boot without proven continuity has every bucket used up and is granted its one boot episode.)
        if (bud_.extra_wakes_micro + 1000000U > wake_limit() || bud_.extra_us >= ext_limit()) {
            ++stats_.wake_denied;
            st_ = State::BudgetBlocked;
            ep_over_ = true;
            ep_extra_ = false;
            last_reason_ = kWakeDenied;
            emit(last_reason_);
            deny_pending_ = true; // the driver came up before the policy was known: it goes off again, unused, once (after_step)
            return;
        }
        bud_.extra_wakes_micro += 1000000U;
    }
    if (sleepy_mode()) {
        begin_episode(wake_reason_, now);
    }
}

void Power::on_job_done(Handle, Status s, MonoTime now) {
    store::RecordJob *job = rec_;
    const bool live = policy_job_; // false after stop(): the memory is returned, the result discarded
    policy_job_ = zombie_ = false;
    rec_ = nullptr;
    if (job == nullptr) {
        return;
    }
    if (!live) {
        engine_.identity().return_record();
        return;
    }
    Policy applied;
    const bool decoded = decode_policy(ByteView{job->payload.data(), job->payload_len}, applied) == Status::Ok;
    engine_.identity().return_record(); // (zeroes the payload: read it first)
    if (s == Status::Ok && decoded) { // the commit of lm_power_policy_set: only now does the new policy apply
        policy_ = applied;
        ++state_gen_;      // a ticket in hand no longer describes this node
        ++stats_.flash_commits;
        next_window_ = MonoTime::never();
        begin_episode(kWindow, now); // a sleepy policy starts its first episode, ALWAYS_RX clears it
    }
    finish_op(policy_op_, s, now);
}

// ---- episodes ---------------------------------------------------------------------------------------
void Power::begin_episode(uint32_t reason, MonoTime now) {
    ++stats_.episodes;
    wake_reason_ = reason;
    ep_over_ = search_ended_ = window_closed_ = false;
    poll_ = Poll{};
    poll_.want = sleepy_mode();
    cont_start_ = MonoTime::never();
    search_used_ms_ = 0;
    if (st_ == State::BudgetBlocked) {
        st_ = State::Running;
    }
    if (!sleepy_mode()) {
        ep_end_ = overrun_at_ = window_end_ = MonoTime::never();
        return;
    }
    ep_start_ = now;
    ep_end_ = now + Duration::from_ms(policy_.awake_budget_ms - policy_.shutdown_reserve_ms);
    overrun_at_ = now + Duration::from_ms(policy_.awake_budget_ms + policy_.shutdown_overrun_ms);
    window_end_ = now + Duration::from_ms(policy_.rx_window_ms);
    if (policy_.mode == k_windowed_rx && next_window_.is_never()) {
        next_window_ = now + Duration::from_ms(policy_.wake_interval_ms);
    }
    last_reason_ = kNone;
    emit(reason);
    engine_.chan().on_episode(now); // the channel search of the last episode was cut by the sleep: this one starts it again
    on_parent_ready(now); // a parent link kept in RAM needs no attach: poll at once
}

void Power::end_of_budget(MonoTime) {
    ep_over_ = true;
    if (st_ == State::Running) {
        st_ = State::BudgetBlocked;
    }
    last_reason_ = kEpisodeBudgetEnd;
    emit(kEpisodeBudgetEnd);
}

void Power::emit(uint32_t reason, uint64_t operation) {
    engine_.emit_event(LM_EVENT_POWER, reason, operation, nullptr);
}

bool Power::asleep() const { return engine_.radio_state() == RadioState::Asleep; }

bool Power::offline() const {
    const route::Mesh::State s = engine_.mesh().state();
    return s != route::Mesh::State::Ready && s != route::Mesh::State::Root && s != route::Mesh::State::Off;
}

// ---- budgets ----------------------------------------------------------------------------------------
void Power::advance_budgets(MonoTime now) {
    if (!settled_) {
        return; // the boot budgets wait for the stored policy: no limit of a default policy may touch them
    }
    const int64_t dt = (now - bud_at_).to_ms();
    if (dt <= 0) {
        return;
    }
    bud_at_ = bud_at_ + Duration::from_ms(dt);
    const auto d = static_cast<uint64_t>(dt);
    leak(bud_.offline_us, off_limit(), k_hour_ms, d);
    leak(bud_.extra_us, ext_limit(), k_day_ms, d);
    leak(bud_.extra_wakes_micro, wake_limit(), k_day_ms, d);
    clamp_budgets();
}

// A bucket never holds more than its limit: a new policy with smaller limits takes effect at once.
void Power::clamp_budgets() {
    if (!settled_) {
        return;
    }
    bud_.offline_us = std::min<uint64_t>(bud_.offline_us, off_limit());
    bud_.extra_us = std::min<uint64_t>(bud_.extra_us, ext_limit());
    bud_.extra_wakes_micro = std::min<uint64_t>(bud_.extra_wakes_micro, wake_limit());
}

// Radio-on time and, of it, the part spent without a parent (the hourly budget of docs/20 §8).
void Power::account_radio(MonoTime now) {
    if (acct_at_.is_never()) {
        return;
    }
    const int64_t dt_us = (now - acct_at_).us;
    if (dt_us < 0) {
        return; // never move the accounting origin back across a synchronous wake
    }
    acct_at_ = now;
    if (dt_us <= 0 || engine_.radio_state() != RadioState::Running) {
        acct_offline_ = offline();
        acct_attach_ = engine_.mesh().state() == route::Mesh::State::Attach;
        return;
    }
    const auto dt = static_cast<uint64_t>(dt_us);
    radio_on_us_ += dt;
    advance_budgets(now);
    if (acct_offline_ && sleepy_mode()) {
        bud_.offline_us += dt;
        if (!acct_attach_) { // FIX10-D3: the search budget pays for looking, the awake budget for the handshake that follows
            search_used_ms_ += static_cast<uint32_t>(dt / 1000U);
        }
    }
    if (ep_extra_) {
        bud_.extra_us += dt;
    }
    acct_offline_ = offline();
    acct_attach_ = engine_.mesh().state() == route::Mesh::State::Attach;
}

uint64_t Power::radio_on_us(MonoTime now) {
    account_radio(now);
    return radio_on_us_;
}

uint32_t Power::offline_remaining_ms(MonoTime now) {
    if (!settled_) {
        return 0; // the stored policy is not loaded yet: nothing is granted before its limits are known
    }
    advance_budgets(now);
    const uint64_t limit = off_limit();
    return static_cast<uint32_t>(bud_.offline_us >= limit ? 0 : (limit - bud_.offline_us) / 1000U);
}

// What survives a deep sleep (Pm::retain, RTC memory) and what a cold boot does without: a boot whose
// continuity cannot be shown starts with nothing left (conservative) and is granted its one boot episode.
void Power::save_retained() {
    port::Pm *pm = engine_.pm();
    if (pm == nullptr) {
        return;
    }
    std::array<uint8_t, 32> b{};
    Writer w{MutByteView{b}};
    w.u8(k_retained_magic);
    w.u64be(bud_.offline_us);
    w.u64be(bud_.extra_us);
    w.u64be(bud_.extra_wakes_micro);
    w.u8(bud_.cursor);
    w.u8(bud_.fail_streak);
    w.u8(scan_cursor_);
    if (w.finish() == Status::Ok) {
        pm->retain(ByteView{b.data(), w.size()});
    }
}

// Boot facts only: what the retained bytes hold and how long the sleep was proven to last. The limits they are
// measured against belong to the STORED policy, which is not known yet - settle_boot_budgets() applies them once
// it is (FIX3-D2: a cold boot must not draw on the ALWAYS_RX defaults).
void Power::load_retained(const port::WakeInfo &w) {
    Reader r{ByteView{w.retained.data(), w.retained_len}};
    Budgets b;
    const uint8_t magic = r.u8();
    b.offline_us = r.u64be();
    b.extra_us = r.u64be();
    b.extra_wakes_micro = r.u64be();
    b.cursor = r.u8();
    b.fail_streak = r.u8();
    const uint8_t scan = r.u8();
    ret_proven_ = w.retained_len == k_retained_bytes && magic == k_retained_magic && r.finish() == Status::Ok && w.elapsed_known;
    ret_elapsed_ms_ = w.elapsed_upper_ms;
    bud_ = ret_proven_ ? b : Budgets{};
    scan_cursor_ = ret_proven_ ? scan : 0;
    boot_grant_ = !ret_proven_;
    settled_ = false;
}

// The policy is final: continuity proven -> the sleep refilled the buckets as far as it was proven; otherwise the
// boot starts with every bucket used up ("zero remaining plus one boot episode", docs/20 §8).
void Power::settle_boot_budgets() {
    if (settled_) {
        return;
    }
    settled_ = true;
    if (ret_proven_) {
        leak(bud_.offline_us, off_limit(), k_hour_ms, ret_elapsed_ms_);
        leak(bud_.extra_us, ext_limit(), k_day_ms, ret_elapsed_ms_);
        leak(bud_.extra_wakes_micro, wake_limit(), k_day_ms, ret_elapsed_ms_);
        clamp_budgets();
        return;
    }
    bud_.offline_us = off_limit();
    bud_.extra_us = ext_limit();
    bud_.extra_wakes_micro = wake_limit();
}

bool Power::search_allowed(MonoTime now) {
    if (!sleepy_mode()) {
        return true;
    }
    advance_budgets(now);
    account_radio(now);
    const bool hour = bud_.offline_us < off_limit() || boot_grant_;
    const bool allowed = hour && now >= search_next_ && !ep_over_ && search_used_ms_ < policy_.search_budget_ms;
    if (!allowed && !search_ended_) { // once per episode: the application is told to stop waiting for a parent
        search_ended_ = true;
        last_reason_ = hour ? kSearchBudgetEnd : kOfflineBudget;
        emit(last_reason_);
    }
    return allowed;
}

// When the radio time of a search with no parent reaches the episode's search budget or the hour's offline budget.
uint32_t Power::search_room_ms(MonoTime now) {
    if (!sleepy_mode()) {
        return UINT32_MAX;
    }
    advance_budgets(now);
    account_radio(now);
    const uint64_t hour_left = boot_grant_ ? UINT64_MAX : (bud_.offline_us < off_limit() ? (off_limit() - bud_.offline_us) / 1000U : 0U);
    const uint64_t search_left = search_used_ms_ < policy_.search_budget_ms ? policy_.search_budget_ms - search_used_ms_ : 0U;
    const int64_t ep_left = ep_end_.is_never() ? INT32_MAX : (ep_end_ - now).to_ms();
    if (ep_over_ || now < search_next_ || ep_left <= 0) {
        return 0;
    }
    return static_cast<uint32_t>(std::min<uint64_t>({hour_left, search_left, static_cast<uint64_t>(ep_left), UINT32_MAX}));
}

MonoTime Power::search_due() const {
    if (!sleepy_mode() || search_ended_ || asleep() || acct_at_.is_never() || !offline() ||
        engine_.mesh().state() == route::Mesh::State::Attach) {
        return MonoTime::never();
    }
    const uint64_t used_ms = search_used_ms_ + static_cast<uint64_t>((engine_.step_time() - acct_at_).to_ms());
    uint64_t left = used_ms < policy_.search_budget_ms ? policy_.search_budget_ms - used_ms : 0;
    if (!boot_grant_) {
        const uint64_t lim = off_limit();
        left = std::min<uint64_t>(left, bud_.offline_us < lim ? (lim - bud_.offline_us) / 1000U : 0U);
    }
    return acct_at_ + Duration::from_ms(static_cast<int64_t>(left) + 1);
}

bool Power::handshake_allowed(MonoTime now) const {
    // The slowest step is an estimate (unmeasured: docs/20 §2 asks for the measured p95 once it exists).
    constexpr uint64_t k_step_ms = 1000;
    return locks_ok() && (!sleepy_mode() || (!ep_over_ && can_start_work(policy_, static_cast<uint64_t>((now - ep_start_).to_ms()), k_step_ms)));
}

// ---- admission --------------------------------------------------------------------------------------
Status Power::admit_send(const DeviceId &dest, uint64_t expires_root_ms, MonoTime now) {
    if (!locks_ok()) {
        return Status::Busy; // fail closed: no new work while a lock it needs is not confirmed (retried every step)
    }
    if (sleepy_mode()) {
        if (st_ == State::Quiescing || st_ == State::SleepReady) {
            return Status::Busy; // a sleep is being prepared: nothing new may start (docs/20 §10)
        }
        if (st_ == State::BudgetBlocked || ep_over_) {
            return Status::PowerBudgetExhausted;
        }
    }
    const Status t = root_check_target(dest, expires_root_ms, now);
    if (t == Status::Ok) {
        ++state_gen_; // a new operation: a sleep ticket in hand is stale
    }
    return t;
}

void Power::note_state_change() { ++state_gen_; }

void Power::note_rx(MonoTime now) {
    ++state_gen_;
    if (!window_end_.is_never() && policy_.mode != k_always_rx) { // frames are still coming: the window stays open
        const MonoTime open = now + Duration::from_ms(policy_.rx_window_ms);
        const MonoTime cap = cont_start_.is_never() ? open : cont_start_ + Duration::from_ms(policy_.max_rx_window_ms);
        if (window_end_ < open && now < cap) {
            window_end_ = open < cap ? open : cap;
            window_closed_ = false;
        }
    }
}

void Power::note_uplink(MonoTime now) {
    if (!sleepy_mode() || asleep() || window_end_.is_never()) {
        return;
    }
    const MonoTime open = now + Duration::from_ms(policy_.rx_window_ms);
    const MonoTime cap = cont_start_.is_never() ? open : cont_start_ + Duration::from_ms(policy_.max_rx_window_ms);
    if (window_end_ < open && now < cap) {
        window_end_ = open < cap ? open : cap;
        window_closed_ = false;
    }
}

// ---- operations of the power API -----------------------------------------------------------------------
Power::OpRec Power::new_op(MonoTime now) {
    OpRec r;
    r.id = k_op_power | ++op_counter_;
    r.accepted_ms = r.last_ms = now.to_ms();
    return r;
}

void Power::finish_op(OpRec &r, Status s, MonoTime now) {
    r.final = true;
    r.result = s;
    r.last_ms = now.to_ms();
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(s), r.id, nullptr);
}

Reply Power::get_operation(uint64_t id, lm_operation_t &out) const {
    for (const OpRec *r : {&policy_op_, &prep_op_}) {
        if (r->id != 0 && r->id == id) {
            out = lm_operation_t{};
            out.struct_size = sizeof(out);
            out.abi_version = LM_ABI_VERSION;
            out.operation_id = id;
            out.phase = r->final ? 3U : 1U;
            out.outcome = !r->final ? LM_OUTCOME_PENDING : (r->result == Status::Ok ? LM_OUTCOME_APPLIED : LM_OUTCOME_REJECTED);
            out.reason = static_cast<uint32_t>(r->result);
            out.accepted_mono_ms = r->accepted_ms;
            out.last_evidence_mono_ms = r->last_ms;
            return Reply{Status::Ok, id, 0};
        }
    }
    return Reply{Status::NotFound, 0, 0};
}

Reply Power::policy_set(const Command &cmd, MonoTime now) {
    if (cmd.request == nullptr || cmd.request_size != sizeof(PolicySetRequest)) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    const auto &rq = *static_cast<const PolicySetRequest *>(cmd.request);
    if (policy_job_ || zombie_ || !loaded_ || (st_ != State::Running && st_ != State::BudgetBlocked)) {
        return Reply{Status::Busy, 0, 0};
    }
    if (rq.expected != policy_.revision) {
        return Reply{Status::Conflict, 0, 0};
    }
    if (policy_.revision >= k_u63_max) {
        return Reply{Status::RecoveryRequired, 0, 0}; // no wrap (docs/20 §1)
    }
    if (rq.policy.revision != rq.expected + 1) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    Status s = validate(rq.policy, engine_.config().role);
    if (s == Status::Ok && rq.policy.mode != k_always_rx && engine_.pm() == nullptr) {
        s = Status::Unsupported; // no sleep port: never silently fall back to ALWAYS_RX (docs/20 §1)
    }
    if (s != Status::Ok) {
        return Reply{s, 0, 0};
    }
    store::RecordJob *job = engine_.identity().lend_record();
    if (job == nullptr) {
        return Reply{Status::Busy, 0, 0};
    }
    std::size_t len = 0;
    if (encode_policy(rq.policy, MutByteView{job->payload}, len) != Status::Ok) {
        engine_.identity().return_record();
        return Reply{Status::InvalidArgument, 0, 0};
    }
    job->arm(store::RecordJob::Op::Commit, store::rec::power_policy, 1, len);
    rec_ = job;
    policy_job_ = true;
    if (const Status sub = engine_.submit_job(JobOwner::Power, Handle{}, JobClass::Flash, &store::record_job, job);
        sub != Status::Ok) {
        policy_job_ = false;
        engine_.identity().return_record(rec_);
        return Reply{sub, 0, 0};
    }
    policy_op_ = new_op(now);
    return Reply{Status::Ok, policy_op_.id, 0};
}

// ---- sleep: prepare -> ticket -> enter ----------------------------------------------------------------
Reply Power::prepare(const SleepRequest &req, MonoTime now) {
    if (!sleepy_mode()) {
        return Reply{Status::RoleNotAllowed, 0, 0}; // ALWAYS_RX never stops the radio behind the app's back
    }
    if (req.kind > LM_SLEEP_DEEP || req.sources == 0 || (req.sources & ~(LM_WAKE_TIMER | LM_WAKE_EXTERNAL)) != 0 ||
        req.pending > LM_PENDING_SAVE_AND_SLEEP || req.budget_ms < 100 || req.budget_ms > 300000 ||
        req.sleep_ms > k_day_ms || ((req.sources & LM_WAKE_TIMER) != 0 && req.sleep_ms == 0)) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    if (engine_.pm() == nullptr) {
        return Reply{Status::Unsupported, 0, 0};
    }
    if (prep_active_ || policy_job_ || (st_ != State::Running && st_ != State::BudgetBlocked && st_ != State::SleepReady)) {
        return Reply{Status::Busy, 0, 0};
    }
    ticket_ = Ticket{};
    prep_req_ = req;
    prep_active_ = true;
    prep_gen_ = state_gen_;
    prep_limit_ = now + Duration::from_ms(req.budget_ms);
    prep_from_ = st_ == State::BudgetBlocked ? State::BudgetBlocked : State::Running;
    st_ = State::Quiescing;
    prep_op_ = new_op(now);
    send_report(now);
    progress_prepare(now);
    return Reply{Status::Ok, prep_op_.id, 0};
}

// Nothing in flight that a sleep would cut. Frames waiting for a HOP_ACK are not "in flight": the sender's
// journal (SAVE_AND_SLEEP) or the caller's own wait (REQUIRE_SETTLED) is what keeps them (docs/20 §6).
bool Power::quiet_now() const {
    return !engine_.tx().in_flight() && !engine_.delivery().job_pending() && !engine_.role_job_pending() &&
           !engine_.identity().busy() && !policy_job_ && !engine_.jobs_busy() && !engine_.chan().unsettled();
}

void Power::progress_prepare(MonoTime now) {
    if (!prep_active_) {
        return;
    }
    auto fail = [&](Status s) {
        prep_active_ = false;
        st_ = prep_from_;
        finish_op(prep_op_, s, now);
    };
    if (state_gen_ != prep_gen_) {
        ++stats_.ticket_stale;
        fail(Status::SleepTicketStale); // something arrived while draining: nothing is dropped, ask again
        return;
    }
    const delivery::Settle sv = engine_.delivery().settle_state();
    const bool committed = sv.uncommitted == 0 && quiet_now();
    const bool settled = prep_req_.pending == LM_PENDING_SAVE_AND_SLEEP ||
                         (sv.active == 0 && sv.owed == 0 && engine_.delivery().hop().in_use() == 0);
    if (committed && settled) {
        prep_active_ = false;
        ticket_.id = ++ticket_seq_;
        ticket_.gen = prep_gen_;
        ticket_.membership = engine_.identity().member().membership.value();
        ticket_.expires = now + k_ticket_life;
        ticket_.valid = true;
        ticket_.taken = false;
        st_ = State::SleepReady;
        finish_op(prep_op_, Status::Ok, now);
        return;
    }
    if (now >= prep_limit_) {
        fail(Status::PowerBudgetExhausted); // did not settle within the budget the caller gave
    }
}

Reply Power::ticket_get(uint64_t op, lm_sleep_ticket_t &out, MonoTime now) {
    if (prep_op_.id == 0 || op != prep_op_.id) {
        return Reply{Status::NotFound, 0, 0};
    }
    if (!prep_op_.final) {
        return Reply{Status::Busy, 0, 0};
    }
    if (prep_op_.result != Status::Ok) {
        return Reply{prep_op_.result, 0, 0}; // a failed prepare issues no ticket
    }
    if (!ticket_.valid || now >= ticket_.expires) {
        return Reply{Status::SleepTicketStale, 0, 0}; // vetoed, used or too old
    }
    if (ticket_.taken) {
        return Reply{Status::Conflict, 0, 0}; // once
    }
    ticket_.taken = true;
    out = lm_sleep_ticket_t{ticket_.id, ticket_.gen, static_cast<uint64_t>(ticket_.expires.to_ms())};
    return Reply{Status::Ok, 0, 0};
}

Reply Power::enter(const lm_sleep_ticket_t &t, MonoTime now) {
    const bool match = ticket_.valid && ticket_.taken && t.id == ticket_.id && t.state_generation == ticket_.gen &&
                       t.expires_mono_ms == static_cast<uint64_t>(ticket_.expires.to_ms());
    const bool fresh = match && now < ticket_.expires && ticket_.gen == state_gen_ &&
                       ticket_.membership == engine_.identity().member().membership.value() && quiet_now();
    ticket_.valid = false; // one use, whatever the outcome
    if (!fresh) {
        ++stats_.ticket_stale;
        if (st_ == State::SleepReady) {
            st_ = prep_from_;
        }
        return Reply{Status::SleepTicketStale, 0, 0};
    }
    const Status st = begin_sleep(prep_req_, false, now);
    if (st != Status::Ok && st_ == State::SleepReady) {
        st_ = prep_from_; // the sleep did not start: back to running, locks as before (the ticket is spent)
        ++state_gen_;
    }
    return Reply{st, 0, 0};
}

Reply Power::sleep_abort(uint64_t op, MonoTime now) {
    if (prep_op_.id == 0 || op != prep_op_.id) {
        return Reply{Status::NotFound, 0, 0};
    }
    if (st_ != State::Quiescing && st_ != State::SleepReady) {
        return Reply{Status::Conflict, 0, 0};
    }
    const bool was_preparing = prep_active_;
    prep_active_ = false;
    ticket_.valid = false; // the application vetoes: radio and locks go back to normal
    st_ = prep_from_;
    last_reason_ = kSleepAborted;
    if (was_preparing) {
        finish_op(prep_op_, Status::SleepTicketStale, now); // the veto: what prepare promised no longer stands
    }
    emit(kSleepAborted, op);
    return Reply{Status::Ok, op, 0};
}

// The sleep itself. The records are committed and nothing is on the air; the radio driver stops (RAM kept for
// LIGHT), the facts the wake will need are noted, and the port starts the sleep.
Status Power::begin_sleep(const SleepRequest &req, bool automatic, MonoTime now) {
    port::Pm *pm = engine_.pm();
    if (pm == nullptr) {
        return Status::Unsupported;
    }
    account_radio(now);
    advance_budgets(now);
    const bool had_radio = engine_.radio_state() == RadioState::Running;
    // The driver must be confirmed stopped before anything else happens: a sleep with a driver that may still call
    // back is no sleep (FIX3-D3). Nothing below has been touched yet, so a failure leaves the node as it was.
    if (const Status rs = engine_.radio_sleep(); rs != Status::Ok) {
        ++stats_.sleep_refused;
        last_reason_ = kSleepAborted;
        return rs;
    }
    // Session facts at entry (docs/20 §7): what would still be valid when we wake.
    const RootTimeBound b = engine_.delivery().root_time(now);
    const member::MemberCredential &mc = engine_.identity().member();
    sl_auth_ms_ = b.valid && b.term == mc.root_term && mc.lease_expires_root_ms > b.latest_ms
                      ? static_cast<int64_t>(mc.lease_expires_root_ms - b.latest_ms)
                      : 0;
    const Duration key = engine_.delivery().min_key_life(now);
    sl_key_ms_ = key.us > 0 ? key.to_ms() : 0;
    sl_life_ms_ = std::min(sl_auth_ms_, sl_key_ms_);
    // An episode that ended without a parent counts towards the offline backoff (exponential, jitter <= 20 %). Only an
    // episode that had the radio on searched: a wake the budget denied leaves the backoff exactly as it was.
    if (!had_radio) {
        // radio off: nothing was searched
    } else if (offline()) {
        bud_.fail_streak = static_cast<uint8_t>(std::min<int>(bud_.fail_streak + 1, 20));
        bud_.cursor = static_cast<uint8_t>(bud_.cursor + 1);
        Duration d = Duration::from_ms(policy_.retry_min_ms);
        for (uint8_t i = 1; i < bud_.fail_streak && d.to_ms() < policy_.retry_max_ms; ++i) {
            d = Duration{d.us * 2};
        }
        d = d.to_ms() > policy_.retry_max_ms ? Duration::from_ms(policy_.retry_max_ms) : d;
        std::array<uint8_t, 2> rnd{};
        engine_.random(MutByteView{rnd});
        const uint64_t jitter_us = static_cast<uint64_t>(d.us) / 5U * (uint32_t{rnd[0]} << 8U | rnd[1]) / 65536U;
        search_next_ = now + d + Duration::from_us(static_cast<int64_t>(jitter_us));
    } else {
        bud_.fail_streak = 0;
        bud_.cursor = 0;
        search_next_ = MonoTime{};
    }
    SleepRequest r = req;
    if (automatic && offline()) { // a WINDOWED node with no parent sleeps longer instead of searching every window
        const uint64_t backoff = static_cast<uint64_t>((search_next_ - now).to_ms());
        const uint64_t refill = refill_ms(bud_.offline_us, off_limit(), k_hour_ms);
        r.sleep_ms = std::max({r.sleep_ms, backoff, refill});
    }
    boot_grant_ = false;
    cur_ = r;
    auto_ = automatic;
    slept_at_ = now;
    wake_at_ = r.sleep_ms != 0 ? now + Duration::from_ms(static_cast<int64_t>(r.sleep_ms)) : MonoTime::never();
    save_retained();
    st_ = State::Sleeping;
    ++stats_.sleeps;
    last_reason_ = kSleepEntered;
    set_locks(now);
    if (r.kind == LM_SLEEP_LIGHT && lock_have_ != 0) { // a lock that could not be released would keep the CPU up
        st_ = State::Running;                          // (deep sleep ends every lock with the reset)
        --stats_.sleeps;
        ++stats_.sleep_refused;
        last_reason_ = kSleepAborted;
        wake_at_ = MonoTime::never();
        engine_.radio_wake(now);
        set_locks(now);
        return Status::Busy;
    }
    port::WakeInfo w;
    switch (pm->sleep(r.kind, r.sources, r.sleep_ms, w)) {
    case port::SleepStart::Woke:
        wake(w, engine_.clock_now());
        return Status::Ok;
    case port::SleepStart::Pending:
        pending_wake_ = w;
        return Status::Ok;
    case port::SleepStart::Unsupported:
        break;
    }
    engine_.radio_wake(now);
    st_ = State::Running;
    return Status::Unsupported;
}

MonoTime Power::step_asleep(MonoTime now) {
    if (st_ == State::Sleeping && !wake_at_.is_never() && now >= wake_at_) {
        port::WakeInfo w = pending_wake_;
        w.source = LM_WAKE_TIMER;
        w.elapsed_upper_ms = static_cast<uint64_t>((now - slept_at_).to_ms()) + 1U;
        wake(w, now);
        return MonoTime{0}; // awake: the caller runs a normal step
    }
    on_timer(now); // a radio-off episode (a wake the budget denied) still has prepare/ticket timers
    set_locks(now);
    return deadline();
}

void Power::wake(const port::WakeInfo &w, MonoTime now) {
    if (st_ != State::Sleeping) {
        return;
    }
    st_ = State::Waking;
    advance_budgets(now);
    const bool external = w.source == LM_WAKE_EXTERNAL;
    const uint32_t reason = auto_ ? kWindow : (external ? kExternal : kTimer);
    // Quota of unplanned wakes and the offline budget (docs/20 §8): a denied wake leaves the radio off and says so.
    const bool quota_ok = auto_ || !external ||
                          (bud_.extra_wakes_micro + 1000000U <= wake_limit() &&
                           bud_.extra_us < ext_limit());
    const bool search_ok = auto_ || !offline() ||
                           (now >= search_next_ && bud_.offline_us < off_limit());
    if (!quota_ok || !search_ok) {
        ++stats_.wake_denied;
        st_ = State::BudgetBlocked;
        ep_over_ = true;
        ep_extra_ = false;
        wake_reason_ = reason;
        last_reason_ = quota_ok ? kOfflineBudget : kWakeDenied;
        wake_at_ = MonoTime::never();
        emit(last_reason_);
        return; // the radio stays off: the application may read its sensor and sleep again
    }
    if (external) {
        bud_.extra_wakes_micro += 1000000U;
    }
    ep_extra_ = external;
    // docs/20 §7, tests/power_golden.json: the RAM is reused only when every condition holds.
    ResumeFacts f;
    f.cause = auto_ ? Wake::ModemWindow : Wake::LightWake;
    f.complete_ram_state = w.ram_complete;
    f.peer_session_valid = true; // proven (or refuted) by the first authenticated exchange after the wake
    f.elapsed_known = w.elapsed_known;
    f.elapsed_upper_ms = w.elapsed_upper_ms;
    f.authorization_remaining_ms = sl_auth_ms_;
    f.key_remaining_ms = sl_key_ms_;
    last_path_ = session_path(f);
    engine_.radio_wake(now);
    acct_at_ = now;
    if (last_path_ == SessionPath::FreshEdhoc) {
        drop_sessions();
        ++stats_.sessions_dropped;
    } else {
        ++stats_.sessions_kept;
    }
    if (engine_.config().role != Role::Root) {
        engine_.membership().pause_isolation(now - slept_at_);
    }
    engine_.mesh().on_wake(now, last_path_ == SessionPath::FreshEdhoc);
    engine_.delivery().sleep_gap(now - slept_at_);
    if (auto_ && !wake_at_.is_never()) {
        next_window_ = wake_at_ + Duration::from_ms(policy_.wake_interval_ms);
    }
    wake_at_ = MonoTime::never();
    st_ = State::Running;
    begin_episode(reason, now);
    engine_.delivery().hop().pump(now);
}

void Power::drop_sessions() {
    std::array<DeviceId, k_build_limits.neighbors> peers;
    std::size_t n = 0;
    engine_.link().neighbors().for_each([&](Handle, link::Neighbor &nb) {
        if (!nb.join_only && n < peers.size()) {
            peers[n++] = nb.device;
        }
    });
    for (std::size_t i = 0; i < n; ++i) {
        (void)engine_.link().close(peers[i]);
    }
    engine_.delivery().sessions().clear();
}

// ---- timers -----------------------------------------------------------------------------------------
void Power::on_timer(MonoTime now) {
    if (st_ == State::SleepReady && ticket_.valid && now >= ticket_.expires) {
        ticket_.valid = false; // 2000 ms after issue: the application was too slow, the node did not change
        st_ = prep_from_;
    }
    progress_prepare(now);
    if (sleepy_mode() && st_ != State::Sleeping && !asleep()) {
        if (!ep_over_ && !ep_end_.is_never() && now >= ep_end_) {
            end_of_budget(now);
        }
        if (!overrun_at_.is_never() && now >= overrun_at_) {
            overrun_at_ = MonoTime::never();
            ++stats_.overruns;
            last_reason_ = kOverrun;
            emit(kOverrun); // the budget did not stop us: recorded, never hidden (docs/20 §2)
        }
        poll_timer(now);
        if (!search_ended_ && search_due() <= now) {
            (void)search_allowed(now); // the search budget just ran out: say so once
        }
        windowed_timer(now);
        if (engine_.step_time() != now) {
            return; // synchronous wake: the next pass owns all post-wake timers
        }
    }
    expire_mailboxes(now);
    flush_grants(now);
}

// WINDOWED_RX: when the receive window closes and nothing is in flight, the engine sleeps until the next window.
void Power::windowed_timer(MonoTime now) {
    if (!held_window_at_.is_never() && now >= held_window_at_) { // HIL-F7: the window after a held-back sleep
        held_window_at_ = MonoTime::never();
        if (policy_.mode == k_windowed_rx && st_ == State::Running) {
            next_window_ = (next_window_ > now ? next_window_ : now) + Duration::from_ms(policy_.wake_interval_ms);
            begin_episode(kWindow, now);
            return;
        }
    }
    if (window_end_.is_never() || now < window_end_ || st_ == State::Quiescing || st_ == State::SleepReady) {
        return;
    }
    if (continue_poll(now)) {
        return; // the parent still holds frames for us and the continuous window allows another poll
    }
    if (!window_closed_) {
        window_closed_ = true;
        emit(kWindowClosed);
    }
    if (policy_.mode != k_windowed_rx) {
        return;
    }
    const bool waiting = poll_.want && !poll_.granted && poll_.attempts < gen::defaults::power_limits::poll_max_attempts &&
                         engine_.mesh().parent_link_up();
    if (waiting || !quiet_now() || engine_.delivery().hop().in_use() != 0 || engine_.link().exchange().busy()) {
        window_end_ = now + k_busy_retry; // in flight: the window stays open, the episode budget still runs
        window_closed_ = false;
        return;
    }
    if (port::Pm *pm = engine_.pm(); pm != nullptr && !pm->may_sleep(LM_SLEEP_LIGHT)) {
        // HIL-F7: the platform holds the node awake (a maintenance link, a button: leanmesh_idf.h). Nothing is stopped:
        // the radio and the sessions stay, and the next window still opens on time (held_window_at_), polls the parent
        // and asks again when it closes. A held-back sleep is neither a fault nor a lost window.
        ++stats_.sleep_vetoed;
        window_end_ = MonoTime::never();
        held_window_at_ = next_window_ > now ? next_window_ : now + k_veto_retry;
        return;
    }
    SleepRequest r;
    r.kind = LM_SLEEP_LIGHT;
    r.sources = LM_WAKE_TIMER;
    r.pending = policy_.pending;
    const int64_t until = (next_window_ - now).to_ms();
    r.sleep_ms = until > 0 ? static_cast<uint64_t>(until) : policy_.guard_ms;
    if (begin_sleep(r, true, now) != Status::Ok) { // the driver would not stop, or a lock would not go: stay up, look again
        window_end_ = now + k_busy_retry;
        window_closed_ = false;
    }
}

MonoTime Power::deadline() const {
    if (st_ == State::Sleeping) {
        return wake_at_;
    }
    MonoTime d = MonoTime::never();
    d = earliest(d, lock_retry_);
    d = earliest(d, deny_retry_);
    if (prep_active_) {
        d = earliest(d, prep_limit_);
    }
    if (ticket_.valid && st_ == State::SleepReady) {
        d = earliest(d, ticket_.expires);
    }
    if (sleepy_mode() && !asleep()) {
        d = earliest(d, ep_over_ ? MonoTime::never() : ep_end_);
        d = earliest(d, held_window_at_);
        d = earliest(d, overrun_at_);
        d = earliest(d, poll_.retry);
        d = earliest(d, search_due());
        if (policy_.mode == k_windowed_rx && !window_closed_) {
            d = earliest(d, window_end_);
        }
    }
    for (const Child &c : children_) {
        if (c.used) {
            d = earliest(d, c.hold_until);
            d = earliest(d, c.grant_due ? c.grant_at : MonoTime::never());
        }
    }
    return d;
}

// Stops the driver of a denied boot wake once nothing of the boot is in flight (a sleeping owner completes no job);
// until then the mesh is held (Power::holds_radio), so nothing is transmitted. A driver that will not stop is asked again.
void Power::stop_denied_radio(MonoTime now) {
    if (!deny_pending_ || (!deny_retry_.is_never() && now < deny_retry_) || !quiet_now()) {
        return;
    }
    deny_retry_ = MonoTime::never();
    if (engine_.radio_sleep() == Status::Ok) {
        deny_pending_ = false;
    } else {
        deny_retry_ = now + k_lock_retry;
    }
}

void Power::after_step(MonoTime now) {
    stop_denied_radio(now);
    account_radio(now);
    progress_prepare(now);
    set_locks(now);
}

// PM locks are a level, recomputed from what is actually happening: a timeout, a cancel or a failed job that
// ends the activity ends the lock too, and nothing has to remember to release it (docs/20 §11).
void Power::set_locks(MonoTime now) {
    port::Pm *pm = engine_.pm();
    if (pm == nullptr) {
        return;
    }
    uint8_t m = 0;
    if (st_ != State::Sleeping && !asleep()) {
        m |= port::pm_lock::episode;
    }
    if (engine_.crypto_busy()) {
        m |= port::pm_lock::crypto;
    }
    if (engine_.flash_busy()) {
        m |= port::pm_lock::flash;
    }
    if (engine_.tx().in_flight()) {
        m |= port::pm_lock::radio;
    }
    // Desired and confirmed are kept apart (FIX3-D4): the port reports what it actually holds, and any difference
    // is asked for again at the next step. The level is never assumed.
    if (m != lock_want_ || lock_have_ != m) {
        lock_want_ = m;
        lock_have_ = pm->set_locks(m);
        if (lock_have_ != m) {
            ++stats_.lock_faults;
        }
    }
    // A lock that is not what it should be is asked for again after a moment, whether or not anything else happens.
    lock_retry_ = lock_have_ == lock_want_ ? MonoTime::never() : now + k_lock_retry;
}

// ---- commands ---------------------------------------------------------------------------------------
Reply Power::execute(const Command &cmd, MonoTime now) {
    advance_budgets(now);
    switch (cmd.kind) {
    case CommandKind::PowerPolicyGet:
        if (cmd.response == nullptr || cmd.response_size != sizeof(Policy)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        *static_cast<Policy *>(cmd.response) = policy_;
        return Reply{Status::Ok, 0, 0};
    case CommandKind::PowerPolicySet:
        return policy_set(cmd, now);
    case CommandKind::PowerGet:
        if (cmd.response == nullptr || cmd.response_size != sizeof(lm_power_snapshot_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        fill_snapshot(*static_cast<lm_power_snapshot_t *>(cmd.response), now);
        return Reply{Status::Ok, 0, 0};
    case CommandKind::SleepPrepare: { // the thin entry: configured policy, DEEP, timer wake (docs/20 §10)
        if (cmd.request == nullptr || cmd.request_size != sizeof(uint32_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        SleepRequest r;
        r.kind = LM_SLEEP_DEEP;
        r.sources = LM_WAKE_TIMER;
        r.pending = policy_.pending;
        r.budget_ms = *static_cast<const uint32_t *>(cmd.request);
        r.sleep_ms = policy_.wake_interval_ms;
        return prepare(r, now);
    }
    case CommandKind::SleepPrepareEx:
        if (cmd.request == nullptr || cmd.request_size != sizeof(SleepRequest)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return prepare(*static_cast<const SleepRequest *>(cmd.request), now);
    case CommandKind::SleepTicketGet:
        if (cmd.request == nullptr || cmd.request_size != sizeof(uint64_t) || cmd.response == nullptr ||
            cmd.response_size != sizeof(lm_sleep_ticket_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return ticket_get(*static_cast<const uint64_t *>(cmd.request), *static_cast<lm_sleep_ticket_t *>(cmd.response), now);
    case CommandKind::SleepEnter:
        if (cmd.request == nullptr || cmd.request_size != sizeof(lm_sleep_ticket_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return enter(*static_cast<const lm_sleep_ticket_t *>(cmd.request), now);
    case CommandKind::SleepAbort:
        if (cmd.request == nullptr || cmd.request_size != sizeof(uint64_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return sleep_abort(*static_cast<const uint64_t *>(cmd.request), now);
    default:
        return Reply{Status::Unsupported, 0, 0};
    }
}

void Power::fill_snapshot(lm_power_snapshot_t &out, MonoTime now) {
    account_radio(now);
    out = lm_power_snapshot_t{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    out.validity_bits = valid::state | valid::radio_on_us | valid::handshakes | valid::flash_commits | valid::budgets;
    out.policy_revision = policy_.revision;
    out.mode = policy_.mode;
    out.state = static_cast<uint32_t>(st_);
    out.wake_reason = wake_reason_;
    out.last_reason = last_reason_;
    out.radio_on_us = radio_on_us_;
    out.episode_count = stats_.episodes;
    out.handshake_count = engine_.link().stats().hs_completed;
    out.flash_commits = stats_.flash_commits + engine_.delivery().stats().journal_puts;
    out.polls = stats_.polls;
    out.missed_windows = stats_.missed_windows;
    out.overruns = stats_.overruns;
    const bool episode = sleepy_mode() && !ep_end_.is_never() && st_ != State::Sleeping;
    out.remaining_awake_ms = episode && now < ep_end_ ? static_cast<uint32_t>((ep_end_ - now).to_ms()) : 0;
    out.offline_budget_remaining_ms = offline_remaining_ms(now);
    if (st_ == State::Sleeping && !wake_at_.is_never() && (cur_.sources & LM_WAKE_TIMER) != 0) {
        out.next_wake_quality = k_quality_bounded;
        out.validity_bits |= valid::next_wake;
    } else {
        out.next_wake_quality = k_quality_unknown;
    }
}

} // namespace lm::power
