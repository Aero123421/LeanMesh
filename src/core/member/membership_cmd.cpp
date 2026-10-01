// Engine::execute for the membership commands (lm_membership_get, lm_join, lm_leave,
// lm_install_control for tickets/expected sets, lm_get_request, root-local join decision).
#include <cstring>

#include "core/engine.hpp"

namespace lm {

Reply Engine::execute_membership(const Command &cmd, MonoTime now) {
    switch (cmd.kind) {
    case CommandKind::MembershipGet: {
        if (cmd.response == nullptr || cmd.response_size != sizeof(lm_membership_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        lm_membership_t out{};
        if (is_root()) {
            member::Membership::view(ident_, nullptr, MonoTime{}, out); // P8: the root holds no joiner side
        } else {
            membership().get_membership(out, now);
        }
        std::memcpy(cmd.response, &out, sizeof(out));
        return Reply{Status::Ok, 0, 0};
    }
    case CommandKind::ConnectivityGet: { // docs/07: independent of the membership state (ACTIVE+ISOLATED is normal)
        if (cmd.response == nullptr || cmd.response_size != sizeof(lm_connectivity_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        lm_connectivity_t out{};
        out.struct_size = sizeof(out);
        out.abi_version = LM_ABI_VERSION;
        if (ident_.is_member()) {
            if (power_.state() == power::Power::State::Sleeping) {
                out.state = LM_SLEEPING;
            } else {
                out.state = mesh_.connectivity(now);
            }
            out.validity_bits = LM_CONNECTIVITY_VALID_STATE;
            if (out.state == LM_ISOLATED || out.state == LM_DEGRADED) {
                out.reason = static_cast<uint32_t>(Status::NoRoute);
            }
            if (mesh_.state() == route::Mesh::State::Ready) {
                out.state_since_mono_ms = mesh_.ready_since().to_ms();
                out.root_depth = mesh_.depth();
                out.validity_bits |= LM_CONNECTIVITY_VALID_STATE_SINCE | LM_CONNECTIVITY_VALID_ROOT_DEPTH;
            } else if (mesh_.state() == route::Mesh::State::Root) {
                out.root_depth = 0;
                out.validity_bits |= LM_CONNECTIVITY_VALID_ROOT_DEPTH;
            }
        } // not a member: UNKNOWN, no validity bit (the membership state says why)
        std::memcpy(cmd.response, &out, sizeof(out));
        return Reply{Status::Ok, 0, 0};
    }
    case CommandKind::PolicyGet:
    case CommandKind::PolicySet:
        return execute_policy(cmd, now);
    case CommandKind::Join: {
        if (is_root()) {
            return Reply{Status::RoleNotAllowed, 0, 0}; // a root is provisioned, it does not join
        }
        if (cmd.request == nullptr || cmd.request_size != sizeof(lm_join_request_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        const auto &r = *static_cast<const lm_join_request_t *>(cmd.request);
        member::JoinArgs a;
        std::memcpy(a.request.bytes.data(), r.request_id.bytes, 16);
        a.mode = r.mode;
        a.search_budget_ms = r.search_budget_ms;
        std::memcpy(a.target.bytes.data(), r.target_domain.bytes, 16);
        a.constrain = r.constrain_target != 0;
        uint64_t op = 0;
        const Status s = membership().join(a, now, op);
        return Reply{s, s == Status::Ok ? op : 0, 0};
    }
    case CommandKind::Leave: {
        if (is_root()) {
            return Reply{Status::RoleNotAllowed, 0, 0};
        }
        if (cmd.request == nullptr || cmd.request_size != sizeof(member::LeaveArgs)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        const auto &a = *static_cast<const member::LeaveArgs *>(cmd.request);
        uint64_t op = 0;
        const Status s = membership().leave(static_cast<uint8_t>(a.mode), a.deadline_ms, now, op);
        return Reply{s, s == Status::Ok ? op : 0, 0};
    }
    case CommandKind::InstallControl: {
        if (cmd.request == nullptr || cmd.request_size != sizeof(uint32_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        uint64_t op = 0;
        Status s = Status::Unsupported; // other control types belong to other slices
        const uint32_t type = *static_cast<const uint32_t *>(cmd.request);
        switch (type) {
        case member::k_type_assignment_ticket: // [S18] on the root: a member of this domain moved away
        case member::k_type_root_handover:     // [S18] a member's authorisation for its domain's new root
            s = is_root() ? ledger().install_lifecycle(static_cast<uint8_t>(type), cmd.payload, now, op)
                          : membership().install_ticket(cmd.payload, now, op);
            break;
        case member::k_type_expected_set:
            s = is_root() ? ledger().install_expected(cmd.payload, now, op) : Status::RoleNotAllowed;
            break;
        case member::k_type_revoke: // [S18]
        case member::k_type_commissioning_window:
            s = is_root() ? ledger().install_lifecycle(static_cast<uint8_t>(type), cmd.payload, now, op)
                          : Status::RoleNotAllowed;
            break;
        default:
            break;
        }
        return Reply{s, s == Status::Ok ? op : 0, 0};
    }
    case CommandKind::GetRequest: {
        if (cmd.request == nullptr || cmd.request_size != sizeof(lm_request_id_t) || cmd.response == nullptr ||
            cmd.response_size != sizeof(lm_operation_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        RequestId id;
        std::memcpy(id.bytes.data(), static_cast<const lm_request_id_t *>(cmd.request)->bytes, 16);
        lm_operation_t out{};
        // The root joins nothing: its own requests do not exist (the Host asks its ledger through the bridge).
        const Status s = is_root() ? Status::NotFound : membership().get_request(id, out, now);
        if (s == Status::Ok) {
            std::memcpy(cmd.response, &out, sizeof(out));
        }
        return Reply{s, 0, 0};
    }
    case CommandKind::TransferNonce: { // [S18]
        std::array<uint8_t, 16> nonce{};
        if (is_root() || cmd.response == nullptr || cmd.response_size != nonce.size()) {
            return Reply{is_root() ? Status::RoleNotAllowed : Status::InvalidArgument, 0, 0};
        }
        const Status s = membership().transfer_nonce(nonce);
        if (s == Status::Ok) {
            std::memcpy(cmd.response, nonce.data(), nonce.size());
        }
        return Reply{s, 0, 0};
    }
    case CommandKind::RootJoinDecide: {
        if (!is_root() || cmd.request == nullptr || cmd.request_size != sizeof(root::JoinDecision)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return Reply{ledger().decide(*static_cast<const root::JoinDecision *>(cmd.request), now), 0, 0};
    }
    default:
        return Reply{Status::Unsupported, 0, 0};
    }
}

// lm_policy_get/set: non-root owns the persisted local auto-transfer policy; root owns network
// policy. FIX8-D12 (review M10): the join mode is a policy field like the channel freeze. One
// policy revision counts every committed change - the coordinator's channel changes plus the
// ledger's join-mode changes, each kept in its own record - and a set is a compare-and-set on it.
// One field changes per call: channel_freeze through the coordinator, join_mode through the ledger
// (durable before its operation ends, CLOSED if that commit's result is unknown). Root
// relay_allowed and automatic transfer are read-only. No field lowers a docs/06 condition: every
// join still needs a fleet-signed ticket, and preapproved a signed entry.
Reply Engine::execute_policy(const Command &cmd, MonoTime now) {
    if (!is_root()) {
        if (cmd.kind == CommandKind::PolicyGet) {
            if (cmd.response == nullptr || cmd.response_size != sizeof(lm_policy_t)) {
                return Reply{Status::InvalidArgument, 0, 0};
            }
            lm_policy_t local{};
            const Status st = membership().local_policy(local);
            std::memcpy(cmd.response, &local, sizeof(local));
            return Reply{st, 0, 0};
        }
        if (cmd.request == nullptr || cmd.request_size != sizeof(PolicySetRequest)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        const auto &r = *static_cast<const PolicySetRequest *>(cmd.request);
        const Reply accepted = membership().set_local_policy(r.policy, r.expected_revision, now);
        if (accepted.status == Status::Ok) {
            note_ctl_op(accepted.operation_id, false, LM_OUTCOME_PENDING, 0);
        }
        return accepted;
    }
    const auto v = coord_.view();
    lm_policy_t cur{};
    cur.struct_size = sizeof(cur);
    cur.abi_version = LM_ABI_VERSION;
    cur.revision = v.policy_revision + ledger().policy_changes();
    cur.join_mode = static_cast<uint32_t>(ledger().join_mode());
    cur.relay_allowed = 1; // the root is the tree's origin
    cur.channel_automatic = v.frozen ? 0U : 1U;
    cur.channel_freeze = v.frozen ? 1U : 0U;
    if (cmd.kind == CommandKind::PolicyGet) {
        if (cmd.response == nullptr || cmd.response_size != sizeof(cur)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        std::memcpy(cmd.response, &cur, sizeof(cur));
        return Reply{Status::Ok, 0, 0};
    }
    if (cmd.request == nullptr || cmd.request_size != sizeof(PolicySetRequest)) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    const auto &rq = *static_cast<const PolicySetRequest *>(cmd.request);
    if (ledger().policy_in_doubt()) {
        return Reply{Status::RecoveryRequired, 0, 0}; // the revision itself is in doubt: no compare-and-set on it
    }
    if (rq.expected_revision != cur.revision) {
        return Reply{Status::Conflict, 0, 0}; // compare-and-set on the policy revision
    }
    const lm_policy_t &want = rq.policy;
    if (want.relay_allowed != cur.relay_allowed || want.auto_transfer_on_isolation != 0 ||
        want.isolation_before_transfer_ms != 0) {
        return Reply{Status::Unsupported, 0, 0};
    }
    const bool mode = want.join_mode != cur.join_mode;
    const bool freeze = want.channel_freeze != cur.channel_freeze;
    if (mode && freeze) {
        return Reply{Status::InvalidArgument, 0, 0}; // one field per call: each change is its own operation
    }
    if (mode) {
        const uint64_t op = next_control_op();
        const Status s = ledger().set_policy_mode(static_cast<root::JoinMode>(want.join_mode), op, now);
        return Reply{s, s == Status::Ok ? op : 0, 0};
    }
    if (!freeze) {
        return Reply{Status::Ok, 0, 0}; // nothing changes: applied, no operation
    }
    return coord_.request(want.channel_freeze != 0 ? LM_CHANNEL_FREEZE : LM_CHANNEL_AUTO, v.policy_revision, now);
}

} // namespace lm
