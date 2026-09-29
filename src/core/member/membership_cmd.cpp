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
        membership_.get_membership(out, now);
        std::memcpy(cmd.response, &out, sizeof(out));
        return Reply{Status::Ok, 0, 0};
    }
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
        const Status s = membership_.join(a, now, op);
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
        const Status s = membership_.leave(static_cast<uint8_t>(a.mode), a.deadline_ms, now, op);
        return Reply{s, s == Status::Ok ? op : 0, 0};
    }
    case CommandKind::InstallControl: {
        if (cmd.request == nullptr || cmd.request_size != sizeof(uint32_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        uint64_t op = 0;
        Status s = Status::Unsupported; // other control types belong to other slices
        switch (*static_cast<const uint32_t *>(cmd.request)) {
        case member::k_type_assignment_ticket:
            s = is_root() ? Status::RoleNotAllowed : membership_.install_ticket(cmd.payload, now, op);
            break;
        case member::k_type_expected_set:
            s = is_root() ? ledger_.install_expected(cmd.payload, now, op) : Status::RoleNotAllowed;
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
        const Status s = membership_.get_request(id, out, now);
        if (s == Status::Ok) {
            std::memcpy(cmd.response, &out, sizeof(out));
        }
        return Reply{s, 0, 0};
    }
    case CommandKind::RootJoinDecide: {
        if (!is_root() || cmd.request == nullptr || cmd.request_size != sizeof(root::JoinDecision)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return Reply{ledger_.decide(*static_cast<const root::JoinDecision *>(cmd.request), now), 0, 0};
    }
    default:
        return Reply{Status::Unsupported, 0, 0};
    }
}

} // namespace lm
