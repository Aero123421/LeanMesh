// Device side of the membership lifecycle after the join (docs/06 §7, docs/07 §8, docs/21): the renewal of
// this device's authorisation lease. Every step borrows the identity's record memory for one short chain of
// worker jobs (verify, commit) and gives it back.
#include <cstring>

#include "core/engine.hpp"
#include "core/member/membership.hpp"

namespace lm::member {
namespace {

constexpr Duration k_busy_retry = Duration::from_ms(50);

// A renewal repeats the live credential with a later lease: same device, address, generations, role, relay
// permission and DeviceCredential; the lease is later on the same term's clock, or it is a lease of a newer term (the
// root restarted, ARCH2-D1: a lease of the old clock cannot be compared with one of the new). Anything else is not a
// renewal (a new membership comes by a join). An older term is never taken back.
bool renews(const MemberCredential &live, const MemberCredential &mc) {
    const bool later = mc.root_term == live.root_term ? mc.lease_expires_root_ms > live.lease_expires_root_ms
                                                      : live.root_term < mc.root_term;
    return mc.device == live.device && mc.address == live.address && mc.assignment == live.assignment &&
           mc.membership == live.membership && mc.role == live.role && mc.relay_allowed == live.relay_allowed &&
           mc.credential_hash == live.credential_hash && mc.policy_hash == live.policy_hash && later;
}

} // namespace

void Membership::on_lifecycle_object(const DeviceId &origin, ByteView cose, MonoTime now) {
    const LocalIdentity &id = engine_.identity();
    Envelope env;
    ByteView data;
    MemberCredential mc;
    if (!id.is_member() || origin != id.delegation().root || phase_ != JoinPhase::Idle || leave_ != LeavePhase::Idle ||
        job_in_flight_ || rec_ != nullptr || cose.size() > store::k_max_payload) {
        ++stats_.renew_dropped; // (busy: the root offers it again)
        return;
    }
    if (peek_signed(cose, k_type_revoke, env, data) == Status::Ok) {
        on_revoke_notice(cose, now);
        return;
    }
    if (peek_signed(cose, k_type_member_credential, env, data) != Status::Ok || env.issuer != origin ||
        env.domain != id.delegation().domain || decode_member_credential(data, mc) != Status::Ok ||
        !renews(id.member(), mc) || !lend_record_only()) {
        ++stats_.renew_dropped; // the root offers it again at the next READY that shows the old lease
        return;
    }
    std::memcpy(rec_->payload.data(), cose.data(), cose.size());
    rec_->payload_len = static_cast<uint32_t>(cose.size());
    verify_input_ = ByteView{rec_->payload.data(), cose.size()};
    peer_.delegation = id.delegation(); // the worker reads this copy only
    if (start_verify(Step::RenewVerify) != Status::Ok) {
        ++stats_.renew_dropped;
        engine_.identity().return_record(rec_);
        peer_ = link::JoinPeerOut{};
    }
    (void)now;
}

void Membership::renew_step(Step step, Status s, MonoTime now) {
    if (s == Status::Ok && step == Step::RenewVerify) {
        s = start_flash(Step::RenewCommit, store::RecordJob::Op::Commit, store::rec::membership, k_membership_active,
                        rec_->payload_len, now);
        if (s == Status::Ok) {
            return;
        }
    }
    if (s == Status::Ok) {
        renew_adopt(now); // RenewCommit, or RenewReload: the committed credential is in the record memory
        return;
    }
    // Refused, or the commit's result is unknown (the record is the old or the new credential, both valid): the
    // live credential stays; the root sends the renewal again.
    ++stats_.renew_dropped;
    engine_.identity().return_record(rec_);
    peer_ = link::JoinPeerOut{};
}

// The committed credential goes live once no handshake is sending our bundle, and every link session is made
// again: the fresh handshake is what hands each neighbour the new lease (its old session ends at the old one).
// [P4] A handshake may run for seconds: meanwhile the record memory goes back and the committed credential is read
// again when it may go live (the record is the truth; whatever replaced it since, a leave or a switch, wins).
void Membership::renew_adopt(MonoTime now) {
    renew_adopt_ = false;
    if (engine_.link().exchange().busy()) {
        engine_.identity().return_record(rec_);
        renew_adopt_ = true;
        retry_at_ = now + k_busy_retry;
        return;
    }
    if (rec_ == nullptr) { // it went back while a handshake ran: the committed credential is read again
        if (!lend_record_or_retry(now) ||
            start_flash(Step::RenewReload, store::RecordJob::Op::Load, store::rec::membership, 0, 0, now) != Status::Ok) {
            engine_.identity().return_record(rec_);
            renew_adopt_ = true;
            retry_at_ = now + k_busy_retry;
        }
        return;
    }
    LocalIdentity &id = engine_.identity();
    const ByteView cose{rec_->payload.data(), rec_->payload_len};
    Envelope env;
    ByteView data;
    MemberCredential mc;
    const RootTerm before = id.term();
    const RootTerm old_cred = id.member().root_term;
    if (rec_->state == k_membership_active && peek_signed(cose, k_type_member_credential, env, data) == Status::Ok &&
        decode_member_credential(data, mc) == Status::Ok && renews(id.member(), mc) &&
        id.adopt_member(id.delegation(), mc, cose) == Status::Ok) {
        ++stats_.renewals;
        if (before < id.term()) {
            engine_.on_new_term(now); // the renewal is the root's signed word of its newer term (ARCH2-D1)
        }
        if (old_cred < mc.root_term) {
            // After a root restart every member is renewed within a minute or two: rotating all their links at once
            // made the neighbourhoods lose READY/LEASE records in the churn and re-attach (measured, R07-sim). The
            // rotations of a term-change renewal start at a random point of the next 30 s (ARCH2-D1).
            std::array<uint8_t, 2> r{};
            engine_.random(MutByteView{r});
            engine_.link().hold_rotations(now + Duration::from_ms((uint32_t{r[0]} << 8U | r[1]) % 30000));
        }
        // The root admits by its ledger, never by the lease (S18-D1): the link with it keeps its session.
        const DeviceId &root = id.delegation().root;
        engine_.link().neighbors().for_each([&root](Handle, link::Neighbor &n) {
            n.rotate_wanted = n.rotate_wanted || (!n.join_only && n.cur.active && n.device != root);
        });
    } else {
        ++stats_.renew_dropped;
    }
    id.return_record(rec_);
    peer_ = link::JoinPeerOut{};
}

// ---- revocation notice (docs/06 §7) ----
// The root's signed RevokeObject for this very device (the root sends it before it closes the device's sessions):
// verified on the worker, then the membership ends like an IMMEDIATE leave, with the revocation's floors in the LEFT
// tombstone. The network's refusal never depends on this: it is the device's own erasure, and nothing reports it
// back (a device that never hears the notice is refused all the same, its lease runs out unrenewed).
void Membership::on_revoke_notice(ByteView cose, MonoTime now) {
    if (!lend_record_only()) {
        return;
    }
    std::memcpy(rec_->payload.data(), cose.data(), cose.size());
    rec_->payload_len = static_cast<uint32_t>(cose.size());
    verify_input_ = ByteView{rec_->payload.data(), cose.size()};
    peer_.delegation = engine_.identity().delegation();
    if (start_verify(Step::RevokeVerify) != Status::Ok) {
        engine_.identity().return_record(rec_);
    }
    (void)now;
}

void Membership::revoke_verified(Status s, MonoTime now) {
    const LocalIdentity &id = engine_.identity();
    RevokeObject rv;
    Envelope env;
    ByteView data;
    const bool mine = s == Status::Ok && peek_signed(verify_input_, k_type_revoke, env, data) == Status::Ok &&
                      decode_revoke(data, rv) == Status::Ok && rv.device == id.self() &&
                      (id.member().assignment.value() < rv.assignment_floor ||
                       id.member().membership.value() < rv.membership_floor);
    engine_.identity().return_record(rec_);
    peer_ = link::JoinPeerOut{};
    if (!mine) {
        return; // not for this device, or not below its generations: nothing to erase
    }
    revoke_af_ = rv.assignment_floor;
    revoke_mf_ = rv.membership_floor;
    revoked_ = true; // before the leave: an IMMEDIATE leave may start its tombstone commit at once
    uint64_t op = 0;
    if (leave(LM_LEAVE_IMMEDIATE, 0, now, op) != Status::Ok) {
        revoked_ = false;
    }
}

// ---- switch to another root (transfer, docs/07 §8; handover, docs/21 §8) ----
// The installed object says where to look: a transfer ticket's target domain, or this domain for a RootHandover.
// Nothing installed (or unreadable): nothing authorises a move, and no handshake is spent on finding that out.
void Membership::switch_peeked(Status s, MonoTime now) {
    const LocalIdentity &id = engine_.identity();
    const ByteView obj{rec_->payload.data(), rec_->payload_len};
    Envelope env;
    ByteView data;
    AssignmentTicket t;
    handover_ = s == Status::Ok && peek_signed(obj, k_type_root_handover, env, data) == Status::Ok;
    if (handover_) {
        switch_domain_ = id.delegation().domain;
    } else if (s == Status::Ok && peek_signed(obj, k_type_assignment_ticket, env, data) == Status::Ok &&
               decode_assignment_ticket(data, t) == Status::Ok) {
        switch_domain_ = t.target;
    } else {
        finish_join(s == Status::Ok || s == Status::NotFound ? Status::AuthPending : s, LM_OUTCOME_REJECTED, now);
        return;
    }
    engine_.identity().return_record(rec_);
    begin_discovery(now);
    disc_.clear_suppress();
    emit_state(0);
}

// Boot: a PREPARED record whose credential another root issued, while this device is still a member. A switch was cut
// after the device stored its next credential and before that went live; the new root may already hold it ACTIVE
// (its grant consumed there). The device asks that root again about the same request (docs/07 §10, docs/21 §5),
// never anew, and stays a member of the old one until the answer. Anything else is an older record: ACTIVE outranks it.
void Membership::resume_switch(const store::RecordJob &rec) {
    const LocalIdentity &id = engine_.identity();
    Envelope env;
    ByteView data;
    MemberCredential mc;
    const ByteView cose{rec.payload.data() + k_prepared_head, rec.payload_len - k_prepared_head};
    if (peek_signed(cose, k_type_member_credential, env, data) != Status::Ok ||
        decode_member_credential(data, mc) != Status::Ok || mc.device != id.self() ||
        env.issuer == id.delegation().root || parse_prepared_record(rec) != Status::Ok) {
        return;
    }
    have_prepared_ = true;
    resume_ = true;
    switch_ = true;
    switch_domain_ = env.domain;
    handover_ = env.domain == id.delegation().domain;
    req_.operation = k_op_tag | ++op_counter_;
}

Status Membership::transfer_nonce(std::array<uint8_t, 16> &out) {
    const LocalIdentity &id = engine_.identity();
    if (id.state() != LocalIdentity::State::Ready) {
        return id.state() == LocalIdentity::State::Failed ? Status::RecoveryRequired : Status::AuthPending;
    }
    if (!nonce_valid_) {
        engine_.random(MutByteView{nonce_});
        nonce_valid_ = true;
    }
    out = nonce_;
    return Status::Ok;
}

} // namespace lm::member
