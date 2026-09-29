#include "core/member/membership.hpp"

#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "core/wire/cbor.hpp"
#include "security/crypto.hpp"

namespace lm::member {
namespace {

constexpr Duration k_default_budget = Duration::from_s(30);   // docs/07 §3: one search, at most 30 s
constexpr Duration k_collect = Duration::from_ms(300);       // wait for a shallower offer than the first
constexpr Duration k_busy_retry = Duration::from_ms(50);      // borrowed memory is taken: try again
constexpr Duration k_connect_retry = Duration::from_ms(500);
constexpr Duration k_request_wait = Duration::from_s(310);    // approval timeout 300 s + margin

} // namespace

Membership::Membership(Engine &engine) : engine_(engine), pipe_(engine, k_tag_join) {}

// ---- small helpers ----
uint32_t Membership::hint() const {
    return peer_.known ? link::domain_hint_of(peer_.delegation.domain) : 0;
}

void Membership::emit_state(uint32_t reason) {
    engine_.emit_event(LM_EVENT_MEMBERSHIP, reason, req_.operation, nullptr);
}

// ---- worker plumbing ----
Status Membership::start_flash(Step step, store::RecordJob::Op op, uint16_t id, uint8_t state,
                               std::size_t payload_len, MonoTime /*now*/) {
    if (rec_ == nullptr || job_in_flight_) {
        return Status::Busy;
    }
    rec_->op = op;
    rec_->id = id;
    rec_->state = state;
    rec_->payload_len = static_cast<uint32_t>(payload_len);
    job_slot_ = Handle{0, ++job_gen_};
    LM_TRY(engine_.submit_job(JobOwner::Join, job_slot_, JobClass::Flash, &store::record_job, rec_));
    step_ = step;
    job_in_flight_ = true;
    return Status::Ok;
}

Status Membership::verify_job(port::JobEnv & /*env*/, void *arg) {
    auto &m = *static_cast<Membership *>(arg);
    return check_member_credential(m.peer_.delegation, m.verify_input_, m.req_.mc);
}

Status Membership::start_verify(MonoTime /*now*/) {
    if (job_in_flight_) {
        return Status::Busy;
    }
    job_slot_ = Handle{0, ++job_gen_};
    LM_TRY(engine_.submit_job(JobOwner::Join, job_slot_, JobClass::PublicKey, &verify_job, this));
    step_ = Step::VerifyPrepare;
    job_in_flight_ = true;
    return Status::Ok;
}

void Membership::on_job_done(Handle slot, Status s, MonoTime now) {
    job_in_flight_ = false;
    if (cancelled_) {
        cancelled_ = false;
        step_ = Step::None;
        release_join(); // stop() kept the borrows reserved for this job (zombie rule): the late result is discarded
        return;
    }
    if (slot != job_slot_ || step_ == Step::None) {
        ++stats_.stale_job_completions;
        return;
    }
    const Step step = step_;
    step_ = Step::None;
    flash_done(step, s, now);
}

void Membership::stop() {
    step_ = Step::None;
    if (phase_ != JoinPhase::Idle) {
        phase_ = JoinPhase::Idle;
        req_.outcome = LM_OUTCOME_INDETERMINATE;
    }
    leave_ = LeavePhase::Idle;
    if (job_in_flight_) {
        cancelled_ = true; // the worker may still write into the borrowed record memory: keep it reserved
        if (pipe_.bound()) {
            (void)engine_.link().close_join(pipe_.peer());
        }
        pipe_.reset();
    } else {
        release_join();
    }
    disc_.stop();
    collect_until_ = search_deadline_ = retry_at_ = request_deadline_ = prepared_until_ = MonoTime::never();
    final_wait_until_ = leave_deadline_ = leave_tx_wait_ = MonoTime::never();
    have_prepared_ = false;
    resume_ = false;
    confirm_pending_ = confirm_consume_ = false;
    confirm_at_ = MonoTime::never();
}

void Membership::release_join() {
    if (pipe_.bound()) {
        (void)engine_.link().close_join(pipe_.peer());
    }
    pipe_.reset();
    if (!scratch_.empty()) {
        engine_.link().exchange().return_scratch();
        scratch_ = MutByteView{};
    }
    if (rec_ != nullptr) {
        engine_.identity().return_record();
        rec_ = nullptr;
    }
    have_cand_ = false;
    peer_ = link::JoinPeerOut{};
    apply_pacing(0); // the policy of a proxied join ends with it
}

// ---- boot ----
void Membership::on_identity_ready(MonoTime now) {
    have_prepared_ = false;
    resume_ = false;
    state_since_ = now;
    confirm_pending_ = confirm_consume_ = false;
    confirm_at_ = MonoTime::never();
    if (engine_.config().role == Role::Root) {
        return;
    }
    // A member only cares about an ACTIVATED record (root acknowledgement owed); a stale PREPARED one is
    // ignored because ACTIVE is authoritative. A non-member resumes a PREPARED request.
    if (rec_ != nullptr || engine_.identity().state() != LocalIdentity::State::Ready ||
        (rec_ = engine_.identity().lend_record()) == nullptr) {
        return;
    }
    if (start_flash(Step::BootLoadPrepared, store::RecordJob::Op::Load, store::rec::membership_prepared, 0, 0,
                    now) != Status::Ok) {
        engine_.identity().return_record();
        rec_ = nullptr;
    }
}

// The PREPARED record: request | nonce | prepare hash | MemberCredential COSE. Its content is what
// the device has to present again when it queries the root by request_id.
Status Membership::parse_prepared_record(const store::RecordJob &rec) {
    if (rec.state != k_prepared_state || rec.payload_len <= k_prepared_head ||
        rec.payload_len > k_prepared_head + k_max_member_cose) {
        return Status::NotFound; // consumed/aborted: nothing to resume
    }
    Request r;
    std::memcpy(r.id.bytes.data(), rec.payload.data(), 16);
    std::memcpy(r.nonce.data(), rec.payload.data() + 16, 16);
    std::memcpy(r.prepare_hash.data(), rec.payload.data() + 32, 32);
    Envelope env;
    ByteView data;
    LM_TRY(peek_signed(ByteView{rec.payload.data() + k_prepared_head, rec.payload_len - k_prepared_head},
                       k_type_member_credential, env, data));
    LM_TRY(decode_member_credential(data, r.mc));
    r.membership = r.mc.membership.value();
    r.assignment = r.mc.assignment.value();
    r.prepared_generation = rec.generation;
    r.evidence = kEvRequested | kEvRootStored | kEvDeviceStored;
    r.known = true;
    req_ = r;
    return Status::Ok;
}

// ---- discovery and connection ----
void Membership::begin_discovery(MonoTime now) {
    phase_ = JoinPhase::Discover;
    engine_.random(MutByteView{hello_nonce_});
    have_cand_ = false;
    offers_ = {};
    collect_until_ = MonoTime::never();
    std::array<uint8_t, 2> j{};
    engine_.random(MutByteView{j});
    // Listen 800 ms without transmitting, then the first hello after 0..399 ms of jitter (docs/07 §3). The
    // operation's own budget (search_deadline_) ends the search; the policy object only paces it.
    disc_.begin(now, static_cast<uint16_t>((uint32_t{j[0]} << 8U | j[1]) % 400), true, Duration::from_s(3600));
    retry_at_ = MonoTime::never();
}

void Membership::send_hello(MonoTime now) {
    std::array<uint8_t, wire::k_link_header_bytes + wire::k_bootstrap_header_bytes + 1> frame{};
    std::size_t len = 0;
    if (encode_discovery(false, hello_nonce_, 0, MutByteView{frame}, len) != Status::Ok) {
        return;
    }
    (void)engine_.transmit(MacAddr::broadcast(), ByteView{frame.data(), len}, k_tag_hello, now);
    // A busy radio only costs this hello: the policy object sends the next one a second later.
}

// Offers are hints (docs/07 §3): nothing they say authorises anything, every candidate goes through the full
// bounded handshake. The root itself (depth 0) is taken at once; otherwise the shallowest of the first
// 300 ms wins. A higher expected-list revision than the one we were refused at ends a NOT_EXPECTED hold.
void Membership::discovery(const MacAddr &src, const wire::BootstrapCarrier &c, MonoTime now) {
    OfferHint h;
    if (phase_ != JoinPhase::Discover || c.object_kind != k_obj_join_offer || decode_offer_hint(c.body, h) != Status::Ok) {
        return;
    }
    if (disc_.revision_advanced(h.expected_revision)) {
        disc_.clear_suppress();
        disc_.wake(now, 0);
        not_expected_ = 0;
    }
    if (have_cand_ || c.exchange_id != hello_nonce_) {
        return; // only answers to our own hello are followed
    }
    ++stats_.offers_seen;
    Offer *slot = nullptr;
    for (Offer &o : offers_) {
        if (o.used && o.mac == src) {
            slot = &o;
        }
    }
    for (Offer &o : offers_) {
        if (slot == nullptr && !o.used) {
            slot = &o;
        }
    }
    if (slot == nullptr) {
        return; // three candidates are enough
    }
    *slot = Offer{true, false, src, h.depth, h.expected_revision};
    if (h.depth == 0) {
        choose_offer(now);
    } else if (collect_until_.is_never()) {
        collect_until_ = now + k_collect;
    }
}

// The proxied joiner speaks slower and in smaller steps: a relay needs a moment per frame and each round
// trip crosses `depth` more hops. Bounded (docs/07 §3 does not lengthen the 30 s search).
void Membership::apply_pacing(uint8_t depth) {
    link::LinkPolicy &p = engine_.link().policy();
    const link::LinkPolicy defaults;
    p.rto = depth == 0 ? defaults.rto : Duration::from_ms(1000 + 200 * std::min<int>(depth, 20));
    p.tx_gap = depth == 0 ? defaults.tx_gap : Duration::from_ms(60);
}

void Membership::choose_offer(MonoTime now) {
    collect_until_ = MonoTime::never();
    Offer *best = nullptr;
    for (Offer &o : offers_) {
        if (o.used && !o.tried && (best == nullptr || o.depth < best->depth)) {
            best = &o;
        }
    }
    if (best == nullptr) {
        return;
    }
    best->tried = true;
    cand_ = best->mac;
    cand_revision_ = best->revision;
    have_cand_ = true;
    apply_pacing(best->depth);
    try_connect(now);
}

void Membership::try_connect(MonoTime now) {
    Status st;
    if (engine_.identity().is_member()) {
        st = engine_.link().connect(cand_, now); // RESUME: an ordinary fresh link session
    } else {
        st = engine_.link().exchange().start_join(cand_, &peer_, now);
    }
    if (st == Status::Ok) {
        phase_ = JoinPhase::Connect;
        disc_.note_handshake();
        retry_at_ = MonoTime::never();
        return;
    }
    if (st == Status::Conflict && engine_.identity().is_member()) {
        finish_join(Status::Ok, LM_OUTCOME_APPLIED, now); // a session already exists
        return;
    }
    if (st == Status::Busy || st == Status::RateLimited || st == Status::NoCapacity) {
        retry_at_ = now + k_connect_retry; // local shortage or the 30 s handshake gate: not RF loss
        return;
    }
    finish_join(st, LM_OUTCOME_REJECTED, now);
}

void Membership::exchange_failed(Status why, MonoTime now) {
    if (phase_ != JoinPhase::Connect) {
        return;
    }
    apply_pacing(0);
    have_cand_ = false;
    const bool another = std::any_of(offers_.begin(), offers_.end(), [](const Offer &o) { return o.used && !o.tried; });
    if (!disc_.may_handshake() && !another) {
        finish_join(why, LM_OUTCOME_REJECTED, now);
        return;
    }
    phase_ = JoinPhase::Discover; // one more candidate within the search budget: the next offer, or the next hello
    if (another && disc_.may_handshake()) {
        choose_offer(now);
    }
}

// The root does not expect this device (yet): a hint, not a verdict (docs/07 §3). No hello for 10..60 s, then
// asked again; a higher expected revision heard meanwhile ends the hold at once (J02).
void Membership::not_expected(MonoTime now) {
    release_join();
    phase_ = JoinPhase::Discover;
    offers_ = {};
    collect_until_ = MonoTime::never();
    // The hold is at least the 30 s full-handshake gate towards this root (docs/06 §8: asking again earlier would
    // only be RATE_LIMITED); the next search gets its own budget after the hold. 30 s, then 60 s.
    const Duration hold = Duration::from_s(not_expected_ == 0 ? 30 : 60);
    ++not_expected_;
    disc_.not_expected(now, hold, cand_revision_);
    disc_.wake(now, 0);
    if (budget_default_) { // a caller who gave no budget waits for the next search; an explicit budget is kept
        search_deadline_ = now + hold + k_default_budget;
    }
    emit_state(static_cast<uint32_t>(Status::NotFound));
}

void Membership::session_up(bool initiator, const MacAddr &mac, const DeviceId &peer, ByteView bundle,
                            MonoTime now) {
    if (!initiator || phase_ != JoinPhase::Connect) {
        return;
    }
    JoinBundle b;
    if (join_bundle_parse(bundle, b) != Status::Ok || !lend_record_only()) {
        finish_join(Status::Busy, LM_OUTCOME_REJECTED, now);
        return;
    }
    pipe_.bind(mac, peer, hint());
    std::memcpy(rec_->payload.data(), b.delegation_cose.data(), b.delegation_cose.size());
    phase_ = JoinPhase::PersistDelegation;
    if (start_flash(Step::CommitDelegation, store::RecordJob::Op::Commit, store::rec::root_delegation, 0,
                    b.delegation_cose.size(), now) != Status::Ok) {
        finish_join(Status::Busy, LM_OUTCOME_REJECTED, now);
    }
}

bool Membership::lend_record_only() {
    if (rec_ != nullptr) {
        return true;
    }
    rec_ = engine_.identity().lend_record();
    if (rec_ == nullptr) {
        ++stats_.scratch_busy;
    }
    return rec_ != nullptr;
}

// ---- Flash chain of the joiner ----
void Membership::flash_done(Step step, Status s, MonoTime now) {
    switch (step) {
    case Step::BootLoadPrepared:
        if (s == Status::Ok && engine_.identity().is_member()) {
            parse_activated_record(*rec_);
        } else if (s == Status::Ok && parse_prepared_record(*rec_) == Status::Ok) {
            have_prepared_ = true;
            resume_ = true;
            req_.operation = k_op_tag | ++op_counter_;
        } else if (s != Status::Ok && s != Status::NotFound) {
            engine_.emit_event(LM_EVENT_FAULT, static_cast<uint32_t>(s), 0, nullptr);
        }
        engine_.identity().return_record();
        rec_ = nullptr;
        if (resume_) { // docs/07 §10: ask the root again about the same request, no new approval
            begin_discovery(now);
            search_deadline_ = now + k_default_budget;
            not_expected_ = 0;
            emit_state(0);
        }
        return;

    case Step::CommitDelegation:
        if (s != Status::Ok) {
            finish_join(s, LM_OUTCOME_REJECTED, now);
            return;
        }
        phase_ = JoinPhase::LoadTicket;
        if (start_flash(Step::LoadTicket, store::RecordJob::Op::Load, k_rec_assignment_ticket, 0, 0, now) !=
            Status::Ok) {
            finish_join(Status::Busy, LM_OUTCOME_REJECTED, now);
        }
        return;

    case Step::LoadTicket:
        if (s != Status::Ok) { // no ticket: nothing authorises this device to ask (docs/07 §4)
            finish_join(s == Status::NotFound ? Status::AuthPending : s, LM_OUTCOME_REJECTED, now);
            return;
        }
        request_ready(now);
        return;

    case Step::VerifyPrepare:
        if (s != Status::Ok) {
            finish_join(s == Status::AuthRejected || s == Status::BadFrame ? Status::AuthRejected : s,
                        LM_OUTCOME_REJECTED, now);
            return;
        }
        if (phase_ == JoinPhase::Activate) {
            mc_verified_ = true;
            activate_commit(now); // resume path: the PREPARED credential is verified before it goes live
            return;
        }
        prepared_verified(now);
        return;

    case Step::CommitPrepared:
        if (s != Status::Ok) { // the record may or may not exist: the next boot reads it (INDETERMINATE)
            finish_join(s, LM_OUTCOME_INDETERMINATE, now);
            return;
        }
        have_prepared_ = true;
        req_.prepared_generation = rec_->generation;
        req_.evidence |= kEvRootStored | kEvDeviceStored;
        prepared_until_ = now + Duration::from_ms(req_.reservation_ms);
        engine_.identity().return_record();
        rec_ = nullptr;
        phase_ = JoinPhase::StoredOut;
        emit_state(0);
        send_stored(now);
        return;

    case Step::ActivateLoad:
        activate_loaded(s, now);
        return;

    case Step::ActivateCommit:
        if (s != Status::Ok) { // ACTIVE may or may not be durable: the next boot decides (allowed state)
            finish_join(s, LM_OUTCOME_INDETERMINATE, now);
            return;
        }
        activated_generation_ = rec_->generation;
        if (const Status a = engine_.identity().adopt_member(peer_.delegation, req_.mc,
                                                             ByteView{rec_->payload.data(), rec_->payload_len});
            a != Status::Ok) {
            finish_join(a, LM_OUTCOME_INDETERMINATE, now);
            return;
        }
        req_.evidence |= kEvDeviceActive;
        ++stats_.joins_active;
        {
            // ACTIVE is durable. The record now says "the root's acknowledgement is owed": if JoinActive or the
            // root's answer is lost, the next link session repeats it (docs/21 §5, LC06) instead of guessing.
            Writer w{MutByteView{rec_->payload}};
            w.bytes(req_.id.view());
            w.bytes(ByteView{req_.nonce});
            w.bytes(ByteView{req_.prepare_hash});
            w.u64be(activated_generation_);
            if (w.finish() != Status::Ok ||
                start_flash(Step::ActivateMark, store::RecordJob::Op::Commit, store::rec::membership_prepared,
                            k_prepared_activated, w.size(), now) != Status::Ok) {
                active_out(now);
            }
        }
        return;

    case Step::ActivateMark:
        have_prepared_ = true; // the ACTIVATED record stays until the root acknowledged
        confirm_pending_ = true;
        active_out(now);
        return;

    case Step::ConfirmConsume:
        confirm_consume_ = false;
        engine_.identity().return_record();
        rec_ = nullptr;
        if (phase_ == JoinPhase::ActiveOut) {
            have_prepared_ = false;
            finish_join(Status::Ok, LM_OUTCOME_APPLIED, now);
        } else {
            have_prepared_ = false;
            engine_.emit_event(LM_EVENT_OPERATION, 0, req_.operation, nullptr);
        }
        return;

    case Step::ConsumePrepared:
        have_prepared_ = false;
        finish_join(req_.reason, req_.outcome, now);
        return;

    case Step::InstallTicket:
        install_done(s, now);
        return;

    case Step::LeaveCommit:
    case Step::LeaveFloors:
        leave_flash_done(step, s, now);
        return;

    case Step::None:
        return;
    }
}

MonoTime Membership::deadline() const {
    MonoTime next = earliest(pipe_.deadline(), retry_at_);
    if (phase_ == JoinPhase::Discover) {
        next = earliest(next, earliest(disc_.deadline(), search_deadline_));
        next = earliest(next, collect_until_);
    }
    next = earliest(next, earliest(request_deadline_, prepared_until_));
    next = earliest(next, final_wait_until_);
    next = earliest(next, leave_tx_wait_); // (the DRAIN deadline is folded into it by leave_timer)
    next = earliest(next, confirm_at_);
    return next;
}

void Membership::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    if (pipe_.owns_tag(o.tag)) {
        pipe_.on_tx_outcome(o, now);
    } else if ((o.tag & 0xFFFF0000U) == k_tag_leave) {
        leave_tx_done(o, now);
    }
}

void Membership::on_timer(MonoTime now) {
    if (phase_ != JoinPhase::Idle) {
        const Status e = pipe_.on_timer(now);
        if (e != Status::Ok && phase_ != JoinPhase::Idle) {
            pipe_failed(e, now);
        }
    }
    if (phase_ == JoinPhase::Discover) {
        if (now >= search_deadline_) {
            finish_join(Status::Expired, LM_OUTCOME_EXPIRED, now); // budget spent: not a device fault
            return;
        }
        if (disc_.poll(now) == Discovery::Act::Hello && !have_cand_ && collect_until_.is_never()) {
            send_hello(now);
        }
        if (!have_cand_ && !collect_until_.is_never() && now >= collect_until_) {
            choose_offer(now);
        }
        if (have_cand_ && now >= retry_at_) {
            try_connect(now);
        }
    }
    if (now >= retry_at_ && phase_ != JoinPhase::Discover) {
        retry_at_ = MonoTime::never();
        retry_work(now);
    }
    if (phase_ == JoinPhase::RequestOut && now >= request_deadline_) {
        finish_join(Status::Expired, LM_OUTCOME_EXPIRED, now); // approval never came: ask again later
    } else if (phase_ == JoinPhase::StoredOut && now >= prepared_until_) {
        // The reservation ran out before COMMIT. The PREPARED record stays: a later query decides.
        finish_join(Status::Expired, LM_OUTCOME_EXPIRED, now);
    } else if (phase_ == JoinPhase::ActiveOut && now >= final_wait_until_) {
        // ACTIVE is durable here but the root's acknowledgement never arrived: not "complete".
        finish_join(Status::Expired, LM_OUTCOME_INDETERMINATE, now);
    }
    leave_timer(now);
    if (confirm_pending_ && now >= confirm_at_) {
        send_confirm(now);
    }
}

// The root did not answer `max_attempts` times. What that means depends on how far we got.
void Membership::pipe_failed(Status why, MonoTime now) {
    if (phase_ == JoinPhase::ActiveOut) {
        finish_join(Status::Expired, LM_OUTCOME_INDETERMINATE, now);
    } else if (phase_ == JoinPhase::RequestOut || phase_ == JoinPhase::StoredOut) {
        finish_join(why == Status::Expired ? Status::Expired : why, LM_OUTCOME_EXPIRED, now);
    } else {
        finish_join(why, LM_OUTCOME_REJECTED, now);
    }
}

// A borrow was busy earlier: resume the step that needed it.
void Membership::retry_work(MonoTime now) {
    switch (phase_) {
    case JoinPhase::LoadTicket:
        request_ready(now);
        break;
    case JoinPhase::Verify:
        prepared_verified(now);
        break;
    case JoinPhase::Activate:
        activate(now);
        break;
    default:
        if (retry_consume_) {
            fail_and_consume(req_.reason, now);
        }
        break;
    }
}

} // namespace lm::member
