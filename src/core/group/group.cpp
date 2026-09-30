// Group fan-out: operations, dispatch, results, cancel (docs/22). Snapshot pages are in snapshot.cpp.
#include "core/group/group.hpp"

#include <algorithm>
#include <cstring>
#include <new>

#include "core/engine.hpp"
#include "core/member/membership.hpp"

namespace lm::group {
namespace {

Reply reply(Status s, uint64_t op = 0) { return Reply{s, op, 0}; }

template <class T> bool request_as(const Command &c, const T *&out) {
    out = static_cast<const T *>(c.request);
    return c.request != nullptr && c.request_size == sizeof(T);
}

uint64_t id_of(const Command &c) {
    uint64_t id = 0;
    if (c.request != nullptr && c.request_size == sizeof(id)) {
        std::memcpy(&id, c.request, sizeof(id));
    }
    return id;
}

// The rule Delivery applies to a receipt for an operation that is already final: an unknown outcome
// may become a known one, a stored one may become applied/rejected; nothing definite is rolled back.
bool refines(uint8_t old_outcome, uint8_t new_outcome) {
    return new_outcome != old_outcome &&
           (old_outcome == LM_OUTCOME_INDETERMINATE || old_outcome == LM_OUTCOME_EXPIRED ||
            (old_outcome == LM_OUTCOME_RECEIVED &&
             (new_outcome == LM_OUTCOME_APPLIED || new_outcome == LM_OUTCOME_REJECTED)));
}


} // namespace

// In place: an Op is 1.3 KB, never a temporary on the owner stack.
void Fanout::reset_op(Op &g) { new (&g) Op(); }

Fanout::Fanout(Engine &engine) : engine_(engine) {}

void Fanout::install() {
    engine_.delivery().set_group_hooks(delivery::GroupHooks{this, &child_hook, &gate_hook});
    engine_.delivery().set_control_sink(
        [](void *ctx, const DeviceId &origin, const std::array<uint8_t, 16> &, ByteView payload, MonoTime now) {
            static_cast<Fanout *>(ctx)->on_control(origin, payload, now);
        },
        this);
}

// A finished operation and its per-target outcomes stay queryable across the stop (like Delivery's finished operations);
// what is not final has been ended by end_for_stop() before, so nothing here is open.
void Fanout::stop() {
    for (Op &g : ops_) {
        free_payload(g);
        if (g.kind == Op::Kind::Own && g.st == Op::St::Final) {
            g.live = 0;
        } else {
            reset_op(g);
        }
    }
}

bool Fanout::has_open() const {
    for (const Op &g : ops_) {
        if (g.kind == Op::Kind::Own && g.st != Op::St::Final) {
            return true;
        }
    }
    return false;
}

// lm_stop does not wait: a target whose child never left is cancelled exactly; one that may have left ends
// INDETERMINATE; none is dropped silently (docs/10, FIX9-D4 for groups).
void Fanout::end_for_stop(MonoTime now) {
    for (Op &g : ops_) {
        if (g.kind != Op::Kind::Own || g.st == Op::St::Final) {
            continue;
        }
        g.cancelled = true;
        if (g.st == Op::St::Fetching) {
            g.outcome = LM_OUTCOME_CANCELLED_NOT_SENT;
            end(g);
            continue;
        }
        for (std::size_t i = 0; i < g.total; ++i) {
            DeviceId dev;
            if (g.t[i].phase == LM_TARGET_FINAL) {
                continue;
            }
            if (g.t[i].live == 0) {
                settle(g, i, LM_OUTCOME_CANCELLED_NOT_SENT, 0);
            } else if (device_at(g, i, dev)) {
                (void)engine_.delivery().cancel_child(dev, mid_of(g, i, g.t[i].attempt), now); // exact only if it never left
            }
        }
        for (std::size_t i = 0; i < g.total; ++i) {
            if (g.t[i].phase != LM_TARGET_FINAL) {
                g.t[i].live = 0;
                settle(g, i, LM_OUTCOME_INDETERMINATE, static_cast<uint32_t>(Status::CancelTooLate));
            }
        }
        g.live = 0;
        aggregate(g);
        end(g);
    }
}

// ---- commands ----
bool Fanout::wants(const Command &c) {
    const lm_send_request_t *rq = nullptr;
    const delivery::HostSendRequest *hs = nullptr;
    switch (c.kind) {
    case CommandKind::Send:
        return request_as(c, rq) && rq->destination.kind == LM_DEST_GROUP;
    case CommandKind::RootHostSend:
        return request_as(c, hs) && hs->rq.destination.kind == LM_DEST_GROUP;
    case CommandKind::GetOperation:
    case CommandKind::Cancel:
        return (id_of(c) & k_id_tag) != 0;
    case CommandKind::GroupSet:
    case CommandKind::GroupProgress:
    case CommandKind::GroupTargets:
        return true;
    default:
        return false; // GetMessage: Engine asks Delivery first
    }
}

Reply Fanout::execute(const Command &c, MonoTime now) {
    const lm_send_request_t *rq = nullptr;
    const delivery::HostSendRequest *hs = nullptr;
    const SetRequest *set = nullptr;
    switch (c.kind) {
    case CommandKind::Send:
        return request_as(c, rq) ? send(*rq, c.payload, nullptr, now) : reply(Status::InvalidArgument);
    case CommandKind::RootHostSend:
        return request_as(c, hs) ? send(hs->rq, c.payload, hs, now) : reply(Status::InvalidArgument);
    case CommandKind::Cancel:
        return cancel(id_of(c), now);
    case CommandKind::GetMessage: {
        const lm_message_ref_t *ref = nullptr;
        return request_as(c, ref) && c.response != nullptr && c.response_size == sizeof(lm_operation_t)
                   ? get_message(*ref, *static_cast<lm_operation_t *>(c.response))
                   : reply(Status::NotFound);
    }
    case CommandKind::GetOperation: {
        const Op *g = find(id_of(c));
        if (g == nullptr || c.response == nullptr || c.response_size != sizeof(lm_operation_t)) {
            return reply(g == nullptr ? Status::NotFound : Status::InvalidArgument);
        }
        get_operation(*g, *static_cast<lm_operation_t *>(c.response));
        return reply(Status::Ok, g->id);
    }
    case CommandKind::GroupSet: {
        if (!request_as(c, set)) {
            return reply(Status::InvalidArgument);
        }
        uint64_t op = 0; // FIX8-D10: its LM_EVENT_OPERATION comes once the definition is durable (root.groups)
        const Status s = engine_.groups().set(*set, op, now);
        return s != Status::Ok ? reply(s) : reply(Status::Ok, op);
    }
    case CommandKind::GroupProgress: {
        Op *g = find(id_of(c));
        if (g == nullptr || g->kind != Op::Kind::Own || c.response == nullptr ||
            c.response_size != sizeof(lm_group_progress_t)) {
            return reply(g == nullptr ? Status::NotFound : Status::InvalidArgument);
        }
        return progress(*g, *static_cast<lm_group_progress_t *>(c.response));
    }
    case CommandKind::GroupTargets: {
        auto *tr = const_cast<TargetsRequest *>(static_cast<const TargetsRequest *>(c.request));
        if (c.request == nullptr || c.request_size != sizeof(TargetsRequest)) {
            return reply(Status::InvalidArgument);
        }
        Op *g = find(tr->operation);
        return g == nullptr || g->kind != Op::Kind::Own ? reply(Status::NotFound) : targets(*g, *tr);
    }
    default:
        return reply(Status::Unsupported);
    }
}

// ---- acceptance ----
Op *Fanout::alloc(Op::Kind kind) {
    Op *pick = nullptr;
    for (std::size_t i = 0; i < ops_.size(); ++i) {
        Op &g = ops_[i];
        if (job_ != Job::None && job_op_ == i) {
            continue; // the worker still reads the memory behind this operation's snapshot
        }
        if (g.kind == Op::Kind::Free) {
            pick = &g;
            break;
        }
        if (g.kind == Op::Kind::Own && g.st == Op::St::Final &&
            (pick == nullptr || static_cast<int32_t>(g.seq - pick->seq) < 0)) {
            pick = &g; // the oldest finished operation makes room
        }
    }
    if (pick == nullptr) {
        return nullptr;
    }
    reset_op(*pick);
    pick->kind = kind;
    pick->seq = ++tick_;
    pick->generation = ++gen_;
    return pick;
}

Op *Fanout::find(uint64_t id) {
    for (Op &g : ops_) {
        if (g.kind == Op::Kind::Own && g.id == id) {
            return &g;
        }
    }
    return nullptr;
}

Reply Fanout::send(const lm_send_request_t &rq, ByteView payload, const delivery::HostSendRequest *host,
                   MonoTime now) {
    delivery::Delivery &dv = engine_.delivery();
    if (!engine_.identity().is_member()) {
        return reply(Status::AuthPending);
    }
    if (!dv.ready() || dv.draining()) {
        return reply(Status::Busy); // FIX13-D2: the drain barrier of unicast sends holds for groups too
    }
    if (rq.reserved != 0 || rq.reserved2 != 0 || rq.delivery > LM_APPLIED || rq.priority >= LM_PRIORITY_CONTROL ||
        rq.strict_single_frame > 1 || rq.app_port == 0 || rq.app_port > 65534 || rq.destination.group_id == 0 ||
        rq.destination.group_revision == 0 || rq.destination.group_revision > k_u63_max || rq.expires_root_ms == 0 ||
        rq.root_term == 0) {
        return reply(Status::InvalidArgument); // a fan-out is a command: it has a deadline
    }
    if (rq.storage != LM_VOLATILE || rq.queue_mode != LM_FIFO) {
        return reply(Status::Unsupported); // no compact group journal record (GS09) and no LATEST group yet
    }
    if (payload.size() > delivery::k_msg_bytes) {
        return reply(Status::PayloadTooLarge);
    }
    if (const Status d = dv.deadline_status(rq.expires_root_ms, rq.root_term); d != Status::Ok) {
        return reply(d);
    }
    if (host != nullptr) { // the Host's intent_hash is over the group marker as the target: the root recomputes it
        delivery::IntentFields f;
        f.origin = engine_.identity().self();
        f.target = group_dest(rq.destination.group_id, rq.destination.group_revision);
        f.domain = engine_.identity().delegation().domain;
        f.app_port = rq.app_port;
        f.delivery = static_cast<uint8_t>(rq.delivery);
        f.storage = static_cast<uint8_t>(rq.storage);
        f.priority = static_cast<uint8_t>(rq.priority);
        f.root_term = rq.root_term;
        f.expires_root_ms = rq.expires_root_ms;
        f.payload = payload;
        Sha256Digest h{};
        if (delivery::intent_hash(f, h) != Status::Ok || h != host->hash) {
            return reply(Status::Conflict);
        }
    }
    std::size_t open = 0;
    for (const Op &g : ops_) {
        if (host != nullptr && g.kind == Op::Kind::Own && g.host && g.host_mid == host->mid) {
            return g.host_hash == host->hash ? reply(Status::Ok, g.id) : reply(Status::Conflict);
        }
        open += g.kind == Op::Kind::Own && g.st != Op::St::Final ? 1U : 0U;
    }
    const bool as_root = root_origin();
    if (open >= limits_for(engine_.config().role).group_operations) {
        return reply(Status::NoCapacity);
    }
    Op *g = alloc(Op::Kind::Own);
    const Handle mb = dv.messages().acquire();
    if (g == nullptr || mb.is_none()) {
        if (g != nullptr) {
            reset_op(*g);
        }
        (void)dv.messages().release(mb);
        return reply(Status::NoCapacity); // nothing existed before this call; nothing exists now
    }
    std::memcpy(dv.messages().get(mb)->data.data(), payload.data(), payload.size());
    g->msg = mb;
    g->len = static_cast<uint16_t>(payload.size());
    g->id = next_id();
    g->group_id = rq.destination.group_id;
    g->revision = rq.destination.group_revision;
    g->port = rq.app_port;
    g->delivery = static_cast<uint8_t>(rq.delivery);
    g->priority = static_cast<uint8_t>(rq.priority);
    g->term = rq.root_term;
    g->expires = rq.expires_root_ms;
    g->accepted_ms = now.to_ms();
    g->host = host != nullptr;
    if (host != nullptr) {
        g->host_mid = host->mid;
        g->host_hash = host->hash;
    }
    ++stats_.started;
    if (!as_root) { // the snapshot comes from the root page by page; the send is accepted, the set is not yet known
        g->st = Op::St::Fetching;
        engine_.random(MutByteView{g->req});
        request_page(*g, now);
        return reply(Status::Ok, g->id);
    }
    Status s = engine_.groups().snapshot(g->group_id, g->revision, *g, ids_of(*g));
    if (s == Status::Ok) {
        engine_.random(MutByteView{g->token});
        s = snapshot_hash(*g, g->hash);
    }
    if (s != Status::Ok) {
        free_payload(*g);
        reset_op(*g);
        return reply(s);
    }
    begin(*g, now);
    return reply(Status::Ok, g->id);
}

// The snapshot is complete and verified: reserve the message ids and start (docs/22 §2).
void Fanout::begin(Op &g, MonoTime now) {
    const delivery::Delivery::SeqBlock b = engine_.delivery().reserve_sequences(g.total * k_attempts);
    g.incarnation = b.incarnation;
    g.base = b.first;
    g.st = Op::St::Running;
    ++g.progress;
    if (g.total == 0) {
        g.outcome = LM_OUTCOME_PARTIAL; // an empty group is complete, not "all"
        end(g);
        return;
    }
    pump(g, now);
}

// ---- dispatch ----
std::array<uint8_t, 16> Fanout::mid_of(const Op &g, std::size_t i, unsigned attempt) const {
    return delivery::to_bytes(MessageId{g.incarnation, g.base + static_cast<uint64_t>(attempt) * g.total + i});
}

bool Fanout::locate(const MessageId &m, Op *&g, std::size_t &i, unsigned &attempt) {
    for (Op &x : ops_) {
        if (x.kind == Op::Kind::Own && x.total != 0 && x.incarnation == m.incarnation && m.sequence >= x.base &&
            m.sequence < x.base + static_cast<uint64_t>(x.total) * k_attempts) {
            const uint64_t off = m.sequence - x.base;
            g = &x;
            i = off % x.total;
            attempt = static_cast<unsigned>(off / x.total);
            return true;
        }
    }
    return false;
}

bool Fanout::root_origin() const { return k_root_capable && engine_.config().role == Role::Root; }

bool Fanout::device_at(const Op &g, std::size_t i, DeviceId &out) const {
    if (i >= k_max_targets) {
        return false;
    }
    out = ids_of(g)[i];
    return true;
}

void Fanout::settle(Op &g, std::size_t i, uint8_t outcome, uint32_t reason) {
    Target &t = g.t[i];
    t.phase = LM_TARGET_FINAL;
    t.outcome = outcome;
    t.reason = static_cast<uint8_t>(reason);
    ++g.progress;
    g.progress_due = true;
    g.progress_at = earliest(g.progress_at, engine_.step_time() + k_progress_gap);
}

// One target becomes a Delivery send. False: a local shortage stopped it (try again shortly).
bool Fanout::dispatch(Op &g, std::size_t i, MonoTime now) {
    delivery::Delivery &dv = engine_.delivery();
    Target &t = g.t[i];
    DeviceId dev;
    if (!device_at(g, i, dev)) {
        settle(g, i, LM_OUTCOME_REJECTED, static_cast<uint32_t>(Status::TargetGenerationChanged));
        return true;
    }
    if (root_origin() && !engine_.groups().current(dev, t.assignment, t.membership)) { // latest floor, membership and assignment, just before sending
        settle(g, i, LM_OUTCOME_REJECTED, static_cast<uint32_t>(Status::TargetGenerationChanged));
        return true;
    }
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, dev.bytes.data(), 32);
    rq.app_port = g.port;
    rq.delivery = g.delivery;
    rq.storage = LM_VOLATILE;
    rq.priority = g.priority;
    rq.queue_mode = LM_FIFO;
    rq.root_term = g.term;
    rq.expires_root_ms = g.expires;
    t.live = 1; // before the call: Delivery may finish the child inside it
    ++g.live;
    const delivery::MsgBuf *buf = dv.messages().get(g.msg);
    const Reply r = dv.send_child(rq, ByteView{buf->data.data(), g.len}, mid_of(g, i, t.attempt), now);
    if (r.status == Status::Ok) {
        if (t.phase == LM_TARGET_WAIT_WAKE) {
            t.phase = LM_TARGET_READY; // it left WAIT_WAKE: its live phase now comes from the child
        }
        ++g.progress;
        return true;
    }
    if (t.live != 0) { // no child exists
        t.live = 0;
        --g.live;
    }
    switch (r.status) {
    case Status::NoCapacity:
    case Status::Busy:
    case Status::TimeUncertain:
        return false;
    case Status::Expired:
        settle(g, i, LM_OUTCOME_EXPIRED, static_cast<uint32_t>(r.status));
        return true;
    default:
        settle(g, i, LM_OUTCOME_REJECTED, static_cast<uint32_t>(r.status));
        return true;
    }
}

// A child that has waited for a route or a session for too long steps aside (WAIT_ROUTE) so that the
// targets behind it are not starved; it is dispatched again with a new MessageId of its block.
void Fanout::park(Op &g, std::size_t i, MonoTime now) {
    DeviceId dev;
    parking_op_ = &g;
    parking_ = i;
    if (device_at(g, i, dev)) {
        (void)engine_.delivery().cancel_child(dev, mid_of(g, i, g.t[i].attempt), now);
    }
    parking_op_ = nullptr;
    ++stats_.parked;
}

void Fanout::pump(Op &g, MonoTime now) {
    delivery::Delivery &dv = engine_.delivery();
    g.at = MonoTime::never();
    const uint64_t park_ms = static_cast<uint64_t>(k_park_after.to_ms());
    for (std::size_t i = 0; i < g.total && !g.cancelled; ++i) {
        lm_operation_t o{};
        DeviceId dev;
        const Target &t = g.t[i];
        if (t.live != 0 && t.attempt + 1U < k_attempts && device_at(g, i, dev) &&
            dv.probe(dev, mid_of(g, i, t.attempt), o) && o.phase == 0 && (o.evidence_bits & delivery::ev::sent) == 0 &&
            now.to_ms() >= o.accepted_mono_ms + park_ms) {
            park(g, i, now);
        }
    }
    const std::size_t cap = std::min(k_inflight, static_cast<std::size_t>(k_build_limits.app_messages / 2U));
    bool shortage = false;
    MonoTime wake_at = MonoTime::never();
    for (std::size_t n = 0; n < g.total; ++n) {
        const std::size_t i = (g.cursor + n) % g.total;
        Target &t = g.t[i];
        if (g.cancelled || shortage || t.live != 0 || t.phase == LM_TARGET_FINAL) {
            continue;
        }
        // A target the root knows to be asleep waits at target level: no child, no in-flight slot, so awake targets
        // behind it are served now (WAIT_WAKE, docs/22 §4). Only the root has the schedules.
        DeviceId dev;
        MonoTime at;
        if (root_origin() && device_at(g, i, dev)) {
            const power::Power::WakeWait w = engine_.power().target_wake(dev, g.expires, now, at);
            if (w == power::Power::WakeWait::Unreachable) {
                settle(g, i, LM_OUTCOME_REJECTED, static_cast<uint32_t>(Status::DeadlineUnreachable));
                continue;
            }
            if (w == power::Power::WakeWait::Wait) {
                if (t.phase != LM_TARGET_WAIT_WAKE) {
                    t.phase = LM_TARGET_WAIT_WAKE;
                    ++g.progress;
                }
                wake_at = earliest(wake_at, at);
                continue;
            }
        }
        if (g.live >= cap) {
            continue;
        }
        if (dispatch(g, i, now)) {
            g.cursor = static_cast<uint8_t>((i + 1) % g.total);
        } else {
            shortage = true;
        }
    }
    std::size_t open = 0;
    for (std::size_t i = 0; i < g.total; ++i) {
        open += g.t[i].phase != LM_TARGET_FINAL ? 1U : 0U;
    }
    if (open == 0 && g.live == 0) {
        aggregate(g);
        end(g);
    } else if (shortage) {
        g.at = now + Duration::from_ms(100);
    } else if (g.live != 0) {
        g.at = now + Duration::from_s(1); // a parked look, not a poll: only while a child is in flight
    }
    g.at = earliest(g.at, wake_at); // the next target that leaves WAIT_WAKE (a real deadline, not a poll)
}

// ---- results ----
void Fanout::child_hook(void *ctx, const delivery::Op &c, MonoTime now) { static_cast<Fanout *>(ctx)->child(c, now); }
bool Fanout::gate_hook(void *ctx, const delivery::Op &c, uint64_t a, uint64_t m) {
    return static_cast<Fanout *>(ctx)->gate(c, a, m);
}

bool Fanout::gate(const delivery::Op &c, uint64_t assignment, uint64_t membership) {
    Op *g = nullptr;
    std::size_t i = 0;
    unsigned attempt = 0;
    if (!locate(c.mid, g, i, attempt)) {
        return true;
    }
    return assignment == g->t[i].assignment && membership == g->t[i].membership;
}

// A child is final (or a final one learnt more). Only the target's fields change here; the operation
// looks at them from its own timer.
void Fanout::child(const delivery::Op &c, MonoTime now) {
    Op *g = nullptr;
    std::size_t i = 0;
    unsigned attempt = 0;
    if (!locate(c.mid, g, i, attempt) || attempt != g->t[i].attempt) {
        return;
    }
    Target &t = g->t[i];
    g->at = g->st == Op::St::Running ? now : g->at; // a finished operation only reports the change
    if (g == parking_op_ && i == parking_) { // our own withdrawal of an unsent child: not an outcome
        t.live = 0;
        --g->live;
        t.attempt = static_cast<uint8_t>(t.attempt + 1U);
        t.phase = LM_TARGET_WAIT_ROUTE;
        ++g->progress;
        return;
    }
    if (t.live != 0) {
        t.live = 0;
        --g->live;
    } else if (!refines(t.outcome, c.outcome)) {
        return;
    } else {
        ++stats_.late; // the group is final or this target is: history is kept, the current outcome improves
    }
    settle(*g, i, c.outcome, c.reason);
    t.evidence = static_cast<uint16_t>(c.evidence);
}

void Fanout::aggregate(Op &g) {
    std::array<uint32_t, 10> n{};
    for (std::size_t i = 0; i < g.total; ++i) {
        ++n[std::min<uint8_t>(g.t[i].outcome, 9)];
    }
    const uint8_t ok = g.delivery == LM_APPLIED ? LM_OUTCOME_APPLIED
                                               : (g.delivery == LM_RECEIVED ? LM_OUTCOME_RECEIVED : LM_OUTCOME_SUBMITTED);
    g.outcome = LM_OUTCOME_PARTIAL; // a mixture: the per-target results are the truth
    for (const uint8_t o : {ok, static_cast<uint8_t>(LM_OUTCOME_REJECTED), static_cast<uint8_t>(LM_OUTCOME_EXPIRED),
                            static_cast<uint8_t>(LM_OUTCOME_CANCELLED_NOT_SENT),
                            static_cast<uint8_t>(LM_OUTCOME_INDETERMINATE)}) {
        g.outcome = n[o] == g.total ? o : g.outcome;
    }
    g.reason = g.outcome != ok && g.outcome != LM_OUTCOME_PARTIAL ? g.t[0].reason : 0;
}

void Fanout::free_payload(Op &g) {
    if (!g.released && !g.msg.is_none()) {
        (void)engine_.delivery().messages().release(g.msg);
    }
    g.released = true;
}

void Fanout::end(Op &g) {
    g.st = Op::St::Final;
    g.at = MonoTime::never();
    g.progress_due = false;
    g.progress_at = MonoTime::never();
    ++g.progress;
    free_payload(g);
    engine_.emit_event(LM_EVENT_OPERATION, g.reason, g.id, nullptr);
    engine_.emit_event(LM_EVENT_GROUP_PROGRESS, 0, g.id, nullptr);
}

void Fanout::on_timer(MonoTime now) {
    for (Op &g : ops_) {
        if (g.kind == Op::Kind::Served) {
            if (now >= g.at && !(job_ != Job::None && &ops_[job_op_] == &g)) {
                reset_op(g);
            }
            continue;
        }
        if (g.kind != Op::Kind::Own) {
            continue;
        }
        if (g.st == Op::St::Fetching && now >= g.at) {
            const Status d = engine_.delivery().deadline_status(g.expires, g.term);
            if (d == Status::Expired) {
                g.outcome = LM_OUTCOME_EXPIRED;
                g.reason = static_cast<uint32_t>(d);
                end(g);
            } else if (g.tries >= k_fetch_tries) {
                fetch_failed(g, static_cast<uint32_t>(Status::RootUnavailable));
            } else {
                request_page(g, now);
            }
        } else if (g.st == Op::St::Running && now >= g.at) {
            pump(g, now);
        }
        if (g.progress_due && now >= g.progress_at) {
            g.progress_due = false;
            g.progress_at = MonoTime::never();
            if (g.st == Op::St::Final) { // a late receipt improved a result of a finished operation
                aggregate(g);
                engine_.emit_event(LM_EVENT_OPERATION, g.reason, g.id, nullptr);
            }
            engine_.emit_event(LM_EVENT_GROUP_PROGRESS, 0, g.id, nullptr);
        }
    }
}

MonoTime Fanout::deadline() const {
    MonoTime next = MonoTime::never();
    for (const Op &g : ops_) {
        if (g.kind != Op::Kind::Free) {
            next = earliest(next, earliest(g.at, g.progress_at));
        }
    }
    return next;
}

// ---- cancel / queries ----
Reply Fanout::cancel(uint64_t id, MonoTime now) {
    Op *g = find(id);
    if (g == nullptr) {
        return reply(Status::NotFound);
    }
    if (g->st == Op::St::Final) {
        return reply(Status::CancelTooLate, id);
    }
    g->cancelled = true;
    if (g->st == Op::St::Fetching) {
        g->outcome = LM_OUTCOME_CANCELLED_NOT_SENT;
        end(*g);
        return reply(Status::Ok, id);
    }
    for (std::size_t i = 0; i < g->total; ++i) {
        DeviceId dev;
        if (g->t[i].phase == LM_TARGET_FINAL) {
            continue;
        }
        if (g->t[i].live == 0) {
            settle(*g, i, LM_OUTCOME_CANCELLED_NOT_SENT, 0);
        } else if (device_at(*g, i, dev)) { // exact if nothing left the node; else its result stays unknown
            (void)engine_.delivery().cancel_child(dev, mid_of(*g, i, g->t[i].attempt), now);
        }
    }
    g->at = now;
    pump(*g, now);
    return reply(Status::Ok, id);
}

void Fanout::get_operation(const Op &g, lm_operation_t &out) const {
    out = lm_operation_t{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    out.operation_id = g.id;
    out.phase = g.st == Op::St::Final ? 3U : (g.st == Op::St::Fetching ? 0U : 1U);
    out.outcome = g.st == Op::St::Final ? g.outcome : static_cast<uint8_t>(LM_OUTCOME_PENDING);
    out.reason = g.reason;
    out.evidence_bits = delivery::ev::accepted;
    for (std::size_t i = 0; i < g.total; ++i) {
        out.evidence_bits |= g.t[i].evidence;
    }
    const std::array<uint8_t, 16> mid = g.host ? g.host_mid : delivery::to_bytes(MessageId{g.incarnation, g.base});
    std::memcpy(out.message_id.bytes, mid.data(), 16);
    std::memcpy(out.intent_hash, g.host_hash.data(), 32);
    out.accepted_mono_ms = g.accepted_ms;
}

Reply Fanout::get_message(const lm_message_ref_t &ref, lm_operation_t &out) {
    for (const Op &g : ops_) {
        if (g.kind == Op::Kind::Own && g.host && std::memcmp(g.host_mid.data(), ref.id.bytes, 16) == 0 &&
            std::memcmp(g.host_hash.data(), ref.intent_hash, 32) == 0 &&
            std::memcmp(engine_.identity().self().bytes.data(), ref.origin.bytes, 32) == 0) {
            get_operation(g, out);
            return reply(Status::Ok, g.id);
        }
    }
    return reply(Status::NotFound);
}

Reply Fanout::progress(const Op &g, lm_group_progress_t &out) const {
    out = lm_group_progress_t{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    std::memcpy(out.snapshot_token, g.token.data(), 16);
    std::memcpy(out.snapshot_hash, g.hash.data(), 32);
    out.progress_revision = g.progress;
    if (g.st == Op::St::Fetching) { // the set is not complete (and not verified) yet: no total, no token
        std::memset(out.snapshot_token, 0, 16);
        std::memset(out.snapshot_hash, 0, 32);
        return reply(Status::Ok, g.id);
    }
    uint32_t partial = 0; // no target ever holds PARTIAL
    uint32_t *const count[] = {&out.pending,   &out.received,  &out.applied,       &out.rejected,  &out.expired,
                               &out.cancelled, &out.indeterminate, &out.superseded, &partial,       &out.submitted}; // by LM_OUTCOME_*
    for (std::size_t i = 0; i < g.total; ++i) {
        ++*count[std::min<uint8_t>(g.t[i].outcome, LM_OUTCOME_SUBMITTED)];
    }
    out.total = g.total;
    return reply(Status::Ok, g.id);
}

Reply Fanout::targets(Op &g, TargetsRequest &rq) {
    rq.written = 0;
    rq.total = g.total;
    if (g.st == Op::St::Fetching || rq.token != g.token) {
        return reply(Status::Conflict); // another (or no) snapshot: never a page of a different set
    }
    if (rq.offset > g.total) {
        return reply(Status::InvalidArgument);
    }
    const std::size_t n = std::min<std::size_t>(std::min<std::size_t>(rq.limit, k_page), g.total - rq.offset);
    if (rq.out == nullptr || rq.capacity < n) {
        return reply(Status::BufferTooSmall);
    }
    delivery::Delivery &dv = engine_.delivery();
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t i = rq.offset + k;
        const Target &t = g.t[i];
        lm_group_target_t &o = rq.out[k];
        o = lm_group_target_t{};
        DeviceId dev;
        const bool known = device_at(g, i, dev);
        std::memcpy(o.device.bytes, known ? dev.bytes.data() : DeviceId{}.bytes.data(), 32);
        o.assignment_generation = t.assignment;
        o.membership_generation = t.membership;
        const auto mid = mid_of(g, i, t.attempt);
        std::memcpy(o.message_id.bytes, mid.data(), 16);
        o.outcome = t.outcome;
        o.reason = t.reason;
        o.evidence_bits = t.evidence;
        o.phase = t.phase;
        lm_operation_t c{};
        if (t.live != 0 && known && dv.probe(dev, mid, c)) { // the phase of a live target is its child's
            o.evidence_bits = c.evidence_bits;
            o.phase = c.phase == 1 ? LM_TARGET_SENDING
                                   : (c.phase == 2 ? LM_TARGET_WAIT_RECEIPT
                                                   : (c.reason == static_cast<uint32_t>(Status::NoRoute) ? LM_TARGET_WAIT_ROUTE
                                                                                                         : LM_TARGET_WAIT_AUTH));
        }
    }
    rq.written = n;
    return reply(Status::Ok, g.id);
}

} // namespace lm::group
