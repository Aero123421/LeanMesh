// Bridge: the 15 serial methods (docs/19 §4, protocol/serial.cddl). Every method first validates its
// params against the CDDL bounds (a malformed request is INVALID_ARGUMENT and touches nothing), then
// calls the core through Engine::execute(). Methods whose module has not landed answer UNSUPPORTED:
// the operation does not exist, it is never acknowledged and never faked (docs/19 §7).
#include <algorithm>
#include <cstring>

#include "core/delivery/delivery.hpp"
#include "core/group/group.hpp"
#include "core/member/membership.hpp"
#include "core/wire/cbor_reader.hpp"
#include "serial/bridge.hpp"

namespace lm::serial {
namespace {

constexpr uint64_t k_u32_max = 0xFFFFFFFFULL;

enum Method : uint64_t {
    kCapabilities = 1, kSend, kGetMessage, kCancel, kJoinDecide, kInstall, kNodeQuery, kGroupSnapshot,
    kHostStoreAck, kEventAck, kChannelAction, kSleepWindow, kGetRequest, kGroupSet, kGroupTargets
};

template <std::size_t N> void take(wire::CborReader &r, std::array<uint8_t, N> &out) {
    const ByteView v = r.bstr(N, N);
    if (v.size() == N) {
        std::copy(v.begin(), v.end(), out.begin());
    }
}

} // namespace

Reply Bridge::run(CommandKind kind, const void *request, std::size_t request_size, ByteView payload,
                  void *response, std::size_t response_size) {
    Command cmd;
    cmd.kind = kind;
    cmd.request = request;
    cmd.request_size = request_size;
    cmd.payload = payload;
    cmd.response = response;
    cmd.response_size = response_size;
    return engine_.execute(cmd, usb_.now());
}

void Bridge::snapshot_of(Pending &p, uint64_t op) {
    lm_operation_t o{};
    o.struct_size = sizeof(o);
    o.abi_version = LM_ABI_VERSION;
    if (run(CommandKind::GetOperation, &op, sizeof(op), ByteView{}, &o, sizeof(o)).status == Status::Ok) {
        p.snap = OpSnap::of(o);
        p.has_op = true;
        p.op = op;
        p.result = Result::Snapshot;
    }
}

void Bridge::handle(Pending &p, uint64_t method, ByteView params) {
    switch (method) {
    case kCapabilities: {
        wire::CborReader r{params};
        p.status = r.try_null() && r.finish() == Status::Ok ? Status::Ok : Status::InvalidArgument;
        p.result = p.status == Status::Ok ? Result::Caps : Result::None;
        return;
    }
    case kSend:
        return m_send(p, params);
    case kGetMessage:
        return m_get_message(p, params);
    case kCancel:
        return m_cancel(p, params);
    case kJoinDecide:
        return m_join_decide(p, params);
    case kInstall:
        return m_install(p, params);
    case kNodeQuery:
        return m_node_query(p, params);
    case kHostStoreAck:
        return m_host_store_ack(p, params);
    case kEventAck:
        return m_event_ack(p, params);
    case kGetRequest:
        return m_get_request(p, params);
    case kChannelAction:
        return m_channel(p, params);
    case kGroupSet:
        return m_group_set(p, params);
    case kGroupTargets:
        return m_group_targets(p, params);
    default:
        return m_unsupported(p, method, params);
    }
}

// SEND: the Host is the root's application. The core recomputes the intent_hash and refuses another
// (CONFLICT); the same MessageId + hash again is the same operation (a retry after a lost response).
void Bridge::m_send(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(9, 9);
    delivery::HostSendRequest hs{};
    hs.rq.struct_size = sizeof(hs.rq);
    hs.rq.abi_version = LM_ABI_VERSION;
    hs.rq.destination.kind = LM_DEST_NODE;
    const ByteView dest = r.bstr(32, 32);
    take(r, hs.mid);
    take(r, hs.hash);
    hs.rq.app_port = static_cast<uint16_t>(r.uint_in(1, 65534));
    const uint64_t flags = r.uint_in(0, 31);
    hs.rq.root_term = static_cast<uint32_t>(r.uint_in(0, k_u32_max));
    hs.rq.expires_root_ms = r.uint_in(0, ~uint64_t{0});
    const bool object = r.boolean();
    const ByteView payload = r.bstr(0, 4096);
    const uint32_t delivery = static_cast<uint32_t>(flags & 3U);
    const uint32_t priority = static_cast<uint32_t>((flags >> 2U) & 3U);
    if (r.finish() != Status::Ok || delivery > LM_APPLIED || priority >= LM_PRIORITY_CONTROL) {
        p.status = Status::InvalidArgument; // CONTROL priority is not selectable from outside (docs/08)
        return;
    }
    if (object) {
        p.status = Status::Unsupported; // lm_send_object: the object transfer module has not landed
        return;
    }
    uint32_t group_id = 0;
    uint64_t group_revision = 0;
    if (group::is_group_dest(dest, group_id, group_revision)) { // a group is a marker value (group.hpp)
        hs.rq.destination.kind = LM_DEST_GROUP;
        hs.rq.destination.group_id = group_id;
        hs.rq.destination.group_revision = group_revision;
    } else {
        std::memcpy(hs.rq.destination.node.bytes, dest.data(), 32);
    }
    hs.rq.delivery = static_cast<uint8_t>(delivery);
    hs.rq.storage = (flags & 16U) != 0 ? LM_DURABLE : LM_VOLATILE;
    hs.rq.priority = static_cast<uint8_t>(priority);
    hs.rq.queue_mode = LM_FIFO;
    const Reply rep = run(CommandKind::RootHostSend, &hs, sizeof(hs), payload);
    p.status = rep.status;
    if (rep.status == Status::Ok) {
        ++stats_.send_accepted;
        snapshot_of(p, rep.operation_id);
    } else {
        ++stats_.send_refused;
    }
}

void Bridge::m_get_message(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(4, 4);
    lm_message_ref_t ref{};
    const ByteView origin = r.bstr(32, 32);
    ref.assignment_generation = r.uint_in(0, ~uint64_t{0});
    const ByteView id = r.bstr(16, 16);
    const ByteView hash = r.bstr(32, 32);
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    std::memcpy(ref.origin.bytes, origin.data(), 32);
    std::memcpy(ref.id.bytes, id.data(), 16);
    std::memcpy(ref.intent_hash, hash.data(), 32);
    lm_operation_t o{};
    o.struct_size = sizeof(o);
    o.abi_version = LM_ABI_VERSION;
    const Reply rep = run(CommandKind::GetMessage, &ref, sizeof(ref), ByteView{}, &o, sizeof(o));
    p.status = rep.status;
    if (rep.status == Status::Ok) {
        p.snap = OpSnap::of(o);
        p.has_op = rep.operation_id != 0; // the operation id lets the Host cancel after its own restart
        p.op = rep.operation_id;
        p.result = Result::Snapshot;
    }
}

// CANCEL: an operation id is valid only inside the gateway boot that issued it (docs/19 §3).
void Bridge::m_cancel(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(2, 2);
    const uint64_t boot = r.uint_in(0, ~uint64_t{0});
    const uint64_t op = r.uint_in(0, ~uint64_t{0});
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    if (boot != boot_) {
        p.status = Status::NotFound;
        return;
    }
    const Reply rep = run(CommandKind::Cancel, &op, sizeof(op));
    p.status = rep.status;
    if (rep.status == Status::Ok || rep.status == Status::CancelTooLate) {
        snapshot_of(p, op); // what is known now: "too late" is a fact about the wire, not an outcome
    }
}

// JOIN_DECIDE: the root re-checks that the request still names this device and credential hash and that
// the Host decided on the current ledger revision (docs/19 §4, SEMANTICS 'Control').
void Bridge::m_join_decide(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(5, 5);
    root::JoinDecision d;
    d.verify = true;
    take(r, d.request.bytes);
    take(r, d.device.bytes);
    take(r, d.credential);
    const uint64_t decision = r.uint_in(0, 1);
    const uint64_t revision = r.uint_in(0, ~uint64_t{0});
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    if (revision != engine_.ledger().expected_revision()) {
        p.status = Status::Conflict; // stale: the operator looked at another state of the ledger
        return;
    }
    d.approve = decision == 1;
    p.status = run(CommandKind::RootJoinDecide, &d, sizeof(d)).status;
}

void Bridge::m_install(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(2, 2);
    const auto type = static_cast<uint32_t>(r.uint_in(0, k_u32_max));
    const ByteView object = r.bstr(1, 4096);
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    const Reply rep = run(CommandKind::InstallControl, &type, sizeof(type), object);
    p.status = rep.status;
    if (rep.status == Status::Ok) {
        p.has_op = true; // acceptance only: the operation's end arrives as an OPERATION event
        p.op = rep.operation_id;
        p.result = Result::Ack;
    }
}

void Bridge::m_node_query(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(1, 1); // node-query = [device / nil]
    if (!r.try_null()) {
        take(r, p.filter);
        p.has_filter = true;
    }
    if (r.finish() != Status::Ok) {
        p.has_filter = false;
        p.status = Status::InvalidArgument;
        return;
    }
    p.status = Status::Ok;
    p.result = Result::Nodes;
}

void Bridge::m_host_store_ack(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(6, 6);
    delivery::HostStoreAckRequest a;
    take(r, a.origin.bytes);
    a.assignment = r.uint_in(0, ~uint64_t{0}); // (origin, assignment generation, MessageId) is the identity
    take(r, a.mid);
    take(r, a.hash);
    (void)r.bstr(16, 16);              // journal id and committed sequence are the Host's evidence, not ours
    (void)r.uint_in(0, ~uint64_t{0});
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    p.status = run(CommandKind::RootHostStoreAck, &a, sizeof(a)).status;
    ++stats_.host_store_acks;
    if (p.status == Status::Ok || p.status == Status::NotFound) {
        for (Slot &s : ring_) { // the Host has it (or the root no longer knows it): stop sending it
            if (s.used && s.ev.kind == LM_EVENT_MESSAGE && s.ev.message_id == a.mid && s.ev.peer == a.origin.bytes &&
                s.ev.assignment == a.assignment) {
                s.stored = true;
                settle(s);
            }
        }
    }
    work_due_ = true; // a slot may be free: take the next event
}

void Bridge::m_event_ack(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(2, 2);
    const uint64_t boot = r.uint_in(0, ~uint64_t{0});
    const uint64_t consumed = r.uint_in(0, ~uint64_t{0});
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    if (boot != boot_) {
        p.status = Status::Conflict; // an ACK of another gateway boot never acknowledges these events
        return;
    }
    if (consumed >= next_seq_) {
        p.status = Status::InvalidArgument; // ahead of what was ever sent
        return;
    }
    p.status = Status::Ok;
    for (Slot &s : ring_) {
        if (s.used && s.seq <= consumed) {
            s.acked = true;
            settle(s);
        }
    }
    work_due_ = true;
}

// GET_REQUEST: the lifecycle of a join request as the root's ledger knows it (state = EntryState, 16 =
// waiting for the operator; evidence bits = member::JoinEvidence). Unknown: NOT_FOUND.
void Bridge::m_get_request(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(1, 1);
    RequestId id;
    take(r, id.bytes);
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    const root::LedgerType &led = engine_.ledger();
    root::PendingJoin pj;
    p.snap = OpSnap{};
    p.status = Status::NotFound;
    for (std::size_t i = 0; i < root::k_join_txns; ++i) {
        if (led.pending_join(i, pj) && pj.request == id) {
            p.snap.phase = 16;
            p.snap.evidence_bits = member::kEvRequested;
            p.status = Status::Ok;
        }
    }
    for (std::size_t i = 0; i < root::k_ledger_slots && p.status != Status::Ok; ++i) {
        const root::Entry &e = led.entry(i);
        if (e.state == root::EntryState::Free || e.state == root::EntryState::Expected || !(e.request == id)) {
            continue;
        }
        p.snap.phase = static_cast<uint32_t>(e.state);
        p.snap.evidence_bits = member::kEvRequested | member::kEvRootStored |
                               (e.state == root::EntryState::Active && e.confirmed ? static_cast<uint32_t>(member::kEvRootConfirmed) : 0U);
        p.status = Status::Ok;
    }
    p.result = p.status == Status::Ok ? Result::Request : Result::None;
}

// Methods 8 (GROUP_SNAPSHOT: the Host never fans out, the root does it for it, S15), 11 (CHANNEL_ACTION) and
// 12 (SLEEP_WINDOW) belong to the channel / power slices. Their params are still validated so that a malformed
// request is told apart from a missing feature; the feature answer is UNSUPPORTED (no operation exists).
void Bridge::m_unsupported(Pending &p, uint64_t method, ByteView params) {
    wire::CborReader r{params};
    switch (method) {
    case kGroupSnapshot:
        (void)r.array(4, 4);
        (void)r.uint_in(0, k_u32_max);
        (void)r.uint_in(0, ~uint64_t{0});
        (void)r.uint_in(0, 3);
        if (!r.try_null()) {
            (void)r.bstr(16, 16);
        }
        break;
    case kSleepWindow:
        (void)r.array(3, 3);
        (void)r.bstr(32, 32);
        (void)r.uint_in(0, ~uint64_t{0});
        (void)r.uint_in(0, k_u32_max);
        break;
    default:
        break;
    }
    p.status = r.finish() == Status::Ok ? Status::Unsupported : Status::InvalidArgument;
}

// GROUP_SET: the members of a group as a list of DeviceIds. A CBOR byte string of 32 bytes is `58 20` and its
// content, so the whole list is addressed in place with a stride of 34 (nothing is copied on the owner stack).
void Bridge::m_group_set(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(3, 3);
    group::SetRequest rq;
    rq.group_id = static_cast<uint32_t>(r.uint_in(1, k_u32_max));
    rq.expected_revision = r.uint_in(0, ~uint64_t{0});
    rq.count = r.array(0, group::k_max_targets);
    rq.stride = 34;
    for (std::size_t i = 0; i < rq.count; ++i) {
        const ByteView m = r.bstr(32, 32);
        if (i == 0) {
            rq.members = m.data();
        } else if (m.data() != rq.members + i * rq.stride) {
            r.fail();
        }
    }
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    const Reply rep = run(CommandKind::GroupSet, &rq, sizeof(rq));
    p.status = rep.status;
    if (rep.status == Status::Ok) {
        p.has_op = true; // completes at once (RAM registry); the OPERATION event says so
        p.op = rep.operation_id;
        p.result = Result::Ack;
    }
}

// GROUP_TARGETS: one page of the per-target results of a group operation of this gateway boot. A zero
// token names the operation's own snapshot (the Host does not know it before the first page).
void Bridge::m_group_targets(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(5, 5);
    const uint64_t boot = r.uint_in(0, ~uint64_t{0});
    const uint64_t op = r.uint_in(0, ~uint64_t{0});
    take(r, p.page.token);
    p.page.offset = static_cast<uint32_t>(r.uint_in(0, group::k_max_targets));
    p.page.limit = static_cast<uint32_t>(r.uint_in(1, group::k_page));
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    lm_group_progress_t g{};
    g.struct_size = sizeof(g);
    g.abi_version = LM_ABI_VERSION;
    p.status = boot != boot_ ? Status::NotFound : run(CommandKind::GroupProgress, &op, sizeof(op), ByteView{}, &g, sizeof(g)).status;
    if (p.status != Status::Ok) {
        return;
    }
    const std::array<uint8_t, 16> none{};
    if (p.page.token == none) {
        std::memcpy(p.page.token.data(), g.snapshot_token, 16);
    } else if (std::memcmp(p.page.token.data(), g.snapshot_token, 16) != 0) {
        p.status = Status::Conflict; // another snapshot than this operation's: never a page of a different set
        return;
    }
    p.has_op = true;
    p.op = op;
    p.result = Result::Targets;
}

// [S17] CHANNEL_ACTION = [action 0..2, expected policy revision]: 0 automatic (unfreeze), 1 freeze, 2 recalculate.
// Accepted means the root applied it (freeze / unfreeze) or started the evaluation (recalculate); what the
// evaluation concluded, and every later step of a plan, is reported as channel state, never as this answer.
void Bridge::m_channel(Pending &p, ByteView params) {
    wire::CborReader r{params};
    (void)r.array(2, 2);
    const uint64_t action = r.uint_in(0, 2);
    const uint64_t revision = r.uint_in(0, ~uint64_t{0});
    if (r.finish() != Status::Ok) {
        p.status = Status::InvalidArgument;
        return;
    }
    const std::array<uint64_t, 2> rq{action, revision};
    p.status = run(CommandKind::ChannelRequest, &rq, sizeof(rq)).status;
}

} // namespace lm::serial
