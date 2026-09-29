// Bridge: session events, the reply queue, the event ring and the typed result encoders. The method
// bodies are in bridge_methods.cpp. All maps are deterministic CBOR (keys ordered by length, then bytes).
#include "serial/bridge.hpp"

#include <algorithm>
#include <cstring>

#include "core/member/membership.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"

namespace lm::serial {
namespace {

constexpr std::size_t k_head = 48; // room in front of a body for the record header
// NextEvent copies an event's payload to the caller: the tail of the transmit buffer takes the copy that
// is never used (the message stays in the core's pool and is read from there while the body is built).
constexpr std::size_t k_dump = gen::limits::small_message_bytes;

// The body stands at out[k_head, k_head + n): the record head goes right in front of it.
Status place(MutByteView out, ByteView head, std::size_t n, std::size_t &len) {
    if (head.size() > k_head) {
        return Status::BufferTooSmall;
    }
    std::memmove(out.data() + head.size(), out.data() + k_head, n);
    std::memcpy(out.data(), head.data(), head.size());
    len = head.size() + n;
    return Status::Ok;
}

template <std::size_t N> void key(wire::CborWriter &w, const char (&s)[N]) { w.text(wire::ascii(s)); }

void put_snapshot(wire::CborWriter &w, const OpSnap &o, uint64_t op) {
    w.map(7);
    key(w, "phase");
    w.uint(o.phase);
    key(w, "reason");
    w.uint(o.reason);
    key(w, "outcome");
    w.uint(o.outcome);
    key(w, "operation");
    w.uint(op);
    key(w, "message_id");
    w.bytes(ByteView{o.message_id});
    key(w, "intent_hash");
    w.bytes(ByteView{o.intent_hash});
    key(w, "evidence_bits");
    w.uint(o.evidence_bits);
}

// lm_capabilities_t::enabled_bits -> the names of api/openapi.json.
void put_feature_names(wire::CborWriter &w, uint64_t bits) {
    static constexpr struct {
        uint64_t bit;
        const char *name;
    } k_names[] = {{LM_FEATURE_SMALL_MESSAGE, "SMALL_MESSAGE"},
                   {LM_FEATURE_OBJECT_4K, "OBJECT_4K"},
                   {LM_FEATURE_GROUP_FANOUT_V2, "GROUP_FANOUT_V2"},
                   {LM_FEATURE_POWER_REPORT_ONLY, "POWER_REPORT_ONLY"},
                   {LM_FEATURE_POWER_WINDOWED_RX, "POWER_WINDOWED_RX"},
                   {LM_FEATURE_RAM_SESSION_RETAIN, "RAM_SESSION_RETAIN"},
                   {LM_FEATURE_AUTO_CHANNEL, "AUTO_CHANNEL"},
                   {LM_FEATURE_SIGNED_TRANSFER, "SIGNED_TRANSFER"},
                   {LM_FEATURE_COMMISSIONING_WINDOW, "COMMISSIONING_WINDOW"},
                   {LM_FEATURE_ROOT_HANDOVER, "ROOT_HANDOVER"}};
    std::size_t n = 0;
    for (const auto &f : k_names) {
        n += (bits & f.bit) != 0 ? 1U : 0U;
    }
    w.array(n);
    for (const auto &f : k_names) {
        if ((bits & f.bit) != 0) {
            w.text(ByteView{reinterpret_cast<const uint8_t *>(f.name), std::strlen(f.name)});
        }
    }
}

// Ledger entry state as the Host's membership vocabulary (lm_membership state numbers); the states
// that are not a member of the network (free, expected, aborted, blocked) are not reported.
bool node_state(root::EntryState s, uint32_t &out) {
    switch (s) {
    case root::EntryState::Prepared:
        out = LM_PREPARED;
        return true;
    case root::EntryState::Active:
        out = LM_ACTIVE;
        return true;
    case root::EntryState::Left:
        out = LM_UNASSIGNED;
        return true;
    default:
        return false;
    }
}

} // namespace

Bridge::Bridge(Engine &engine, RootUsb &usb, uint64_t boot_id) : engine_(engine), usb_(usb), boot_(boot_id) {
    engine_.delivery().set_host_gate(true); // the Host's DB commit is the terminal store of every MESSAGE
    usb_.set_bridge(this);
}

std::size_t Bridge::ring_used() const {
    return static_cast<std::size_t>(std::count_if(ring_.begin(), ring_.end(), [](const Slot &s) { return s.used; }));
}

// ---- session ----
void Bridge::on_session(bool up, uint32_t gen, UsbDown) {
    pending_.clear(); // replies computed for an old session are never sent on a new one
    active_ = up;
    gen_ = up ? gen : 0;
    work_due_ = true;
    for (Slot &s : ring_) {
        s.sent_gen = 0; // everything unsettled goes out again under the new session
    }
}

void Bridge::on_record(SerialKind kind, uint8_t lane, uint32_t frame_bytes, ByteView payload, uint32_t) {
    const MonoTime now = usb_.now();
    Pending p;
    p.lane = lane;
    p.frame_bytes = frame_bytes;
    wire::CborReader r{payload};
    (void)r.array(3, 3);
    const ByteView id = r.bstr(16, 16);
    const uint64_t method = r.uint_in(1, 15);
    const ByteView params = r.skip_item();
    if (kind != SerialKind::Request || r.finish() != Status::Ok) {
        ++stats_.malformed; // the Host sends nothing but well-formed REQUESTs; anything else is not answered
        usb_.link().release(lane, 1, frame_bytes, now);
        return;
    }
    std::copy(id.begin(), id.end(), p.request_id.begin());
    ++stats_.requests;
    handle(p, method, params);
    if (!pending_.push(p)) { // cannot happen: the window equals the queue; never block, never fake
        ++stats_.replies_dropped;
        usb_.link().release(lane, 1, frame_bytes, now);
        return;
    }
    work_due_ = true; // a command may have queued events
    flush();
}

// ---- owner step ----
void Bridge::on_step(MonoTime now) {
    if (active_) {
        for (Slot &s : ring_) {
            if (s.used && s.sent_gen == gen_ && now - s.sent_at >= k_event_retry) {
                s.sent_gen = 0; // no settlement for a while: send again (the Host de-duplicates)
                ++stats_.events_resent;
            }
        }
    }
    work_due_ = false;
    flush();
}

MonoTime Bridge::deadline() const {
    if (work_due_) {
        return MonoTime{0};
    }
    MonoTime d = MonoTime::never();
    if (active_) {
        for (const Slot &s : ring_) {
            if (s.used && s.sent_gen == gen_) {
                d = earliest(d, s.sent_at + k_event_retry);
            }
        }
    }
    return d;
}

void Bridge::flush() {
    if (in_flush_) { // the link may call on_tx_ready() while send() is still on the stack
        work_due_ = true;
        return;
    }
    in_flush_ = true;
    flush_replies();
    flush_events();
    in_flush_ = false;
}

// ---- results ----
std::size_t Bridge::encode_result(const Pending &p, MutByteView out) {
    wire::CborWriter w{out};
    switch (p.result) {
    case Result::None:
        return 0;
    case Result::Snapshot:
        put_snapshot(w, p.snap, p.op);
        break;
    case Result::Ack:
        w.map(2);
        key(w, "phase");
        w.uint(0);
        key(w, "reason");
        w.uint(0);
        break;
    case Result::Caps: {
        lm_capabilities_t caps{};
        caps.struct_size = sizeof(caps);
        caps.abi_version = LM_ABI_VERSION;
        (void)run(CommandKind::GetCapabilities, nullptr, 0, ByteView{}, &caps, sizeof(caps));
        const RootTimeBound t = engine_.delivery().root_time(usb_.now());
        const member::LocalIdentity &id = engine_.identity();
        w.map(7);
        key(w, "root");
        w.bytes(id.self().view());
        key(w, "domain");
        w.bytes(id.delegation().domain.view());
        key(w, "enabled");
        put_feature_names(w, caps.enabled_bits);
        key(w, "root_term");
        w.uint(t.valid ? t.term.value() : 0);
        key(w, "root_time");
        if (t.valid) {
            w.array(2);
            w.uint(t.earliest_ms);
            w.uint(t.latest_ms);
        } else {
            w.null();
        }
        key(w, "assignment");
        w.uint(id.is_member() ? id.member().assignment.value() : 0);
        key(w, "gateway_boot");
        w.uint(boot_);
        break;
    }
    case Result::Nodes: {
        const root::LedgerType &led = engine_.ledger();
        std::size_t n = 0;
        for (std::size_t i = 0; i < root::k_ledger_slots; ++i) {
            uint32_t st = 0;
            const root::Entry &e = led.entry(i);
            n += (node_state(e.state, st) && (!p.has_filter || e.device.bytes == p.filter)) ? 1U : 0U;
        }
        w.map(3);
        key(w, "nodes");
        w.array(n);
        for (std::size_t i = 0; i < root::k_ledger_slots; ++i) {
            uint32_t st = 0;
            const root::Entry &e = led.entry(i);
            if (!node_state(e.state, st) || (p.has_filter && e.device.bytes != p.filter)) {
                continue;
            }
            w.array(6);
            w.bytes(e.device.view());
            w.uint(e.assignment);
            w.uint(e.membership);
            w.uint(st);
            w.boolean(e.confirmed);
            w.uint(e.address.value());
        }
        key(w, "pending");
        root::PendingJoin pj;
        std::size_t np = 0;
        for (std::size_t i = 0; i < root::k_join_txns; ++i) {
            np += led.pending_join(i, pj) ? 1U : 0U;
        }
        w.array(np);
        for (std::size_t i = 0; i < root::k_join_txns; ++i) {
            if (led.pending_join(i, pj)) {
                w.array(3);
                w.bytes(pj.request.view());
                w.bytes(pj.device.view());
                w.bytes(ByteView{pj.credential});
            }
        }
        key(w, "revision");
        w.uint(led.expected_revision());
        break;
    }
    case Result::Request:
        w.map(2);
        key(w, "state");
        w.uint(p.snap.phase);
        key(w, "evidence_bits");
        w.uint(p.snap.evidence_bits);
        break;
    }
    return w.finish() == Status::Ok ? w.size() : 0;
}

// RESPONSE = [request id, status, operation / nil, result bytes / nil]. The result is computed here,
// at send time, directly in the transmit buffer (a Busy send builds it again from the same state).
Status Bridge::write_reply(const Pending &p, MutByteView out, std::size_t &len) {
    Status status = p.status;
    const std::size_t n = encode_result(p, MutByteView{out.data() + k_head, out.size() - k_head});
    if (n == 0 && p.result != Result::None) {
        status = Status::PayloadTooLarge; // does not fit the bounds: reported, never a made-up result
    }
    std::array<uint8_t, k_head> hb{};
    wire::CborWriter w{MutByteView{hb}};
    w.array(4);
    w.bytes(ByteView{p.request_id});
    w.uint(static_cast<uint32_t>(status));
    if (p.has_op) {
        w.uint(p.op);
    } else {
        w.null();
    }
    if (n == 0) {
        w.null();
    } else {
        w.bytes_head(n);
    }
    return place(out, w.written(), n, len);
}

void Bridge::flush_replies() {
    while (active_) {
        const Pending *f = pending_.front();
        if (f == nullptr) {
            return;
        }
        WriterFn rw{[this, f](MutByteView out, std::size_t &len) { return write_reply(*f, out, len); }};
        const Status st = usb_.link().send_built(SerialKind::Response, gen_, rw, usb_.now());
        if (st == Status::Busy) {
            return; // no credit / TX busy: on_tx_ready() retries
        }
        Pending done;
        (void)pending_.pop(done);
        ++(st == Status::Ok ? stats_.replies : stats_.replies_dropped);
        usb_.link().release(done.lane, 1, done.frame_bytes, usb_.now());
    }
}

// ---- event ring ----
Bridge::Slot *Bridge::free_slot() {
    for (Slot &s : ring_) {
        if (!s.used) {
            return &s;
        }
    }
    return nullptr;
}

void Bridge::settle(Slot &s) {
    if (s.used && (s.ev.kind == LM_EVENT_MESSAGE ? s.stored : s.acked)) {
        s.used = false;
        ++stats_.events_settled;
    }
}

// EVENT = [boot, seq, kind, body bytes]. With take the slot is free and the next event of the engine's
// queue is taken into it (only here, with the transmit buffer and credit at hand, so a Busy never
// leaves an event that has nowhere to go). Without it the slot's event is sent again.
Status Bridge::write_event(Slot &s, bool take, MutByteView out, std::size_t &len) {
    if (take) {
        lm_event_t e{};
        e.struct_size = sizeof(e);
        e.abi_version = LM_ABI_VERSION;
        Command cmd;
        cmd.kind = CommandKind::NextEvent;
        cmd.response = &e;
        cmd.response_size = sizeof(e);
        cmd.response_payload = MutByteView{out.data() + out.size() - k_dump, k_dump};
        const Reply r = engine_.execute(cmd, usb_.now());
        if (r.status != Status::Ok) {
            return r.status; // NOT_FOUND: nothing queued
        }
        s = Slot{};
        s.used = true;
        s.seq = next_seq_++;
        s.ev = EvRef::of(e);
        ++stats_.events_queued;
    }
    const EvRef &ev = s.ev;
    wire::CborWriter w{MutByteView{out.data() + k_head, out.size() - k_head}};
    if (ev.kind == LM_EVENT_MESSAGE) {
        ByteView payload;
        if (!engine_.delivery().event_payload(ev.event(), payload)) {
            s.used = false; // the core no longer holds it (expired): the Host asks GET_MESSAGE
            ++stats_.events_gone;
            work_due_ = true;
            return Status::NotFound;
        }
        w.map(7);
        key(w, "origin");
        w.bytes(ByteView{ev.peer});
        key(w, "payload");
        w.bytes(payload);
        key(w, "app_port");
        w.uint(ev.app_port);
        key(w, "recovered");
        w.boolean(ev.reason == 1);
        key(w, "message_id");
        w.bytes(ByteView{ev.message_id});
        key(w, "intent_hash");
        w.bytes(ByteView{ev.intent_hash});
        key(w, "assignment_generation");
        w.uint(ev.assignment);
    } else if (ev.kind == LM_EVENT_OPERATION) {
        lm_operation_t o{};
        o.struct_size = sizeof(o);
        o.abi_version = LM_ABI_VERSION;
        const bool message_op = (ev.operation & member::k_op_tag) == 0;
        if (message_op && run(CommandKind::GetOperation, &ev.operation, sizeof(ev.operation), ByteView{}, &o,
                              sizeof(o)).status == Status::Ok) {
            put_snapshot(w, OpSnap::of(o), ev.operation);
        } else { // membership/control operation: the reason is the status of the step that ended it
            w.map(4);
            key(w, "phase");
            w.uint(3);
            key(w, "reason");
            w.uint(ev.reason);
            key(w, "outcome");
            w.uint(ev.reason == 0 ? LM_OUTCOME_APPLIED : LM_OUTCOME_REJECTED);
            key(w, "operation");
            w.uint(ev.operation);
        }
    } else {
        w.map(2);
        key(w, "peer");
        w.bytes(ByteView{ev.peer});
        key(w, "reason");
        w.uint(ev.reason);
    }
    if (w.finish() != Status::Ok) {
        return Status::PayloadTooLarge; // cannot happen: bodies are bounded (payload <= 512 B)
    }
    std::array<uint8_t, k_head> hb{};
    wire::CborWriter h{MutByteView{hb}};
    h.array(4);
    h.uint(boot_);
    h.uint(s.seq);
    h.uint(ev.kind);
    h.bytes_head(w.size());
    return place(out, h.written(), w.size(), len);
}

void Bridge::flush_events() {
    while (active_) {
        Slot *next = nullptr;
        for (Slot &s : ring_) {
            if (s.used && s.sent_gen != gen_ && (next == nullptr || s.seq < next->seq)) {
                next = &s;
            }
        }
        const bool take = next == nullptr;
        if (take) {
            next = free_slot(); // a full ring stops here: the engine's queue and its GAP bound the rest
            if (next == nullptr) {
                return;
            }
        }
        WriterFn ew{[this, next, take](MutByteView out, std::size_t &len) { return write_event(*next, take, out, len); }};
        const Status st = usb_.link().send_built(SerialKind::Event, gen_, ew, usb_.now());
        if (st == Status::NotFound && !take) {
            continue; // that event is gone (counted); look at the next
        }
        if (st != Status::Ok) {
            return; // Busy: on_tx_ready() retries; NotFound: nothing queued; else the session is gone
        }
        next->sent_gen = gen_;
        next->sent_at = usb_.now();
        ++stats_.events_sent;
    }
}

} // namespace lm::serial
