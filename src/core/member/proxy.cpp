#include "core/member/proxy.hpp"

#include <algorithm>
#include <cstring>

#include "core/engine.hpp"
#include "core/link/exchange.hpp"

namespace lm::member {
namespace {

constexpr Duration k_offer_gap = Duration::from_ms(100);
constexpr Duration k_shortage_retry = Duration::from_ms(20);
// The root paces frames towards a joiner: the relay's radio needs a moment per frame and cannot ask for
// more (S11-D3); a joiner paces its own frames the same way (LinkPolicy::tx_gap).
constexpr Duration k_down_gap = Duration::from_ms(60);
constexpr std::size_t k_record_max = wire::k_end_header_bytes + wire::data_capacity(1) + wire::k_tag_bytes;

} // namespace

bool Proxy::is_root() const { return k_root_capable && engine_.config().role == Role::Root; }

void Proxy::stop() {
    for (Entry &e : table_) {
        if (e.used) {
            free_entry(e);
        }
    }
    out_ = Out{};
    in_ = In{};
    retry_at_ = outcome_at_ = MonoTime::never();
}

std::size_t Proxy::entries() const {
    return static_cast<std::size_t>(std::count_if(table_.begin(), table_.end(), [](const Entry &e) { return e.used; }));
}

Proxy::Entry *Proxy::find(const MacAddr &mac) {
    for (Entry &e : table_) {
        if (e.used && e.mac == mac) {
            return &e;
        }
    }
    return nullptr;
}

Proxy::Entry *Proxy::add(const MacAddr &mac, MonoTime now) {
    for (Entry &e : table_) {
        if (!e.used) {
            e = Entry{};
            if (!is_root() && engine_.acquire_peer(mac, PeerClass::Transient, e.peer) != Status::Ok) {
                return nullptr; // no transient driver slot: a local shortage, the joiner asks again
            }
            e.used = true;
            e.mac = mac;
            e.last = now;
            return &e;
        }
    }
    return nullptr;
}

void Proxy::free_entry(Entry &e) {
    if (!e.peer.is_none()) {
        (void)engine_.release_peer(e.peer);
    }
    e = Entry{};
}

void Proxy::on_timer(MonoTime now) {
    for (Entry &e : table_) {
        if (e.used && now - e.last >= k_proxy_idle) {
            free_entry(e);
        }
    }
    if (now >= outcome_at_) {
        outcome_at_ = MonoTime::never();
        engine_.complete_virtual_tx(outcome_tag_, outcome_ok_ ? port::TxResult::MacAcked : port::TxResult::MacFailed, now);
    }
    if (now >= retry_at_) {
        retry_at_ = MonoTime::never();
        if (in_.ready) {
            deliver_in(now);
        }
        pump_out(now);
    }
}

MonoTime Proxy::deadline() const {
    MonoTime d = earliest(retry_at_, outcome_at_);
    for (const Entry &e : table_) {
        if (e.used) {
            d = earliest(d, e.last + k_proxy_idle);
        }
    }
    return d;
}

bool Proxy::route_to(uint16_t dest, delivery::PathSpec &out, MonoTime now) {
    if (is_root()) {
        return engine_.routes().path_to_addr(ShortAddr{dest}, out, now);
    }
    return engine_.mesh().route_to_root(out, now);
}

// ---- relay: hello -> offer, joiner frame -> route ----
void Proxy::answer_hello(const wire::BootstrapCarrier &hello, MonoTime now) {
    if (!k_proxy_built || is_root() || !engine_.mesh().proxy_capable(now) || now < last_offer_ + k_offer_gap) {
        return; // only an attached relay offers, and a hello flood costs one offer per gap
    }
    const ByteView scope = engine_.identity().scope_key();
    OfferHint asked;
    if (decode_hello(hello.body, asked) != Status::Ok || !scope_ok(scope, k_obj_join_hello, hello.exchange_id, asked)) {
        return; // SEC-Da: a scoped relay carries only joins of its own scope
    }
    last_offer_ = now;
    OfferHint h;
    h.depth = engine_.mesh().depth();
    h.expected_revision = engine_.mesh().expected_revision();
    std::array<uint8_t, wire::k_link_header_bytes + wire::k_bootstrap_header_bytes + 14> frame{};
    std::size_t len = 0;
    if (scope_sign(scope, k_obj_join_offer, hello.exchange_id, h) == Status::Ok &&
        encode_discovery(true, hello.exchange_id, link::domain_hint_of(engine_.identity().delegation().domain),
                         MutByteView{frame}, len, &h) == Status::Ok) {
        (void)engine_.transmit(MacAddr::broadcast(), ByteView{frame.data(), len}, k_tag_proxy | 1U, now);
    }
}

bool Proxy::from_joiner(const port::RadioRx &rx, MonoTime now) {
    if (!k_proxy_built || is_root() || rx.broadcast || rx.len < wire::k_link_header_bytes) {
        return false;
    }
    wire::LinkHeader h;
    ByteView payload;
    const ByteView frame{rx.bytes.data(), rx.len};
    if (wire::decode_link_frame(frame, h, payload) != Status::Ok) {
        return false;
    }
    if (h.kind == wire::FrameKind::Edhoc && h.link_sid == 0) {
        // The start of an ordinary link handshake: this device is a member now and talks to us directly.
        if (Entry *joined = find(rx.src); joined != nullptr) {
            free_entry(*joined);
        }
        return false;
    }
    const bool carrier = h.kind == wire::FrameKind::JoinProxy;
    const bool session = h.link_sid != 0 && (h.kind == wire::FrameKind::Edhoc || h.kind == wire::FrameKind::Control);
    if (!carrier && !session) {
        return false;
    }
    link::Neighbors &nb = engine_.link().neighbors();
    if (nb.find_mac(rx.src) != nullptr || nb.has_grace(rx.src)) {
        return false; // a neighbour (or a joiner of our own): the normal link path
    }
    wire::BootstrapCarrier c;
    if (carrier && (wire::decode_bootstrap(payload, c) != Status::Ok || c.object_kind >= k_obj_join_hello)) {
        return false; // hello / offer: discovery, not a tunnelled frame
    }
    if (!engine_.mesh().proxy_capable(now)) {
        return false;
    }
    Entry *e = find(rx.src);
    if (e == nullptr) {
        // Only the start of a handshake (CredI, first fragment) opens a tunnel.
        if (!carrier || c.object_kind != static_cast<uint8_t>(link::ObjKind::CredI) || c.offset != 0) {
            return false; // not the start of a join handshake: some other exchange's frame (a link BIND ...)
        }
        e = add(rx.src, now);
        if (e == nullptr) {
            ++stats_.dropped_full;
            return true;
        }
    }
    e->last = now;
    if (out_.active) {
        ++stats_.dropped_busy; // one frame in the pipe: the joiner's retransmission repeats this one
        return true;
    }
    start_out(rx.src, frame, 0, 0, now, false);
    ++stats_.up;
    return true;
}

// ---- carrying a frame through the route, chunk by chunk ----
void Proxy::start_out(const MacAddr &mac, ByteView frame, uint16_t dest, uint32_t tag, MonoTime now, bool defer) {
    out_ = Out{};
    std::memcpy(out_.bytes.data(), frame.data(), frame.size());
    out_.len = frame.size();
    out_.mac = mac;
    out_.dest = dest;
    out_.tag = tag;
    out_.id = next_id_;
    next_id_ = next_id_ == 255 ? 1 : static_cast<uint8_t>(next_id_ + 1);
    out_.active = true;
    if (defer) {
        retry_at_ = now; // the caller learns the outcome later, never from inside transmit()
    } else {
        pump_out(now);
    }
}

void Proxy::pump_out(MonoTime now) {
    if (!out_.active || out_.inflight) {
        return;
    }
    delivery::PathSpec route;
    if (!route_to(out_.dest, route, now)) {
        finish_out(false, now);
        return;
    }
    const std::size_t cap = wire::data_capacity(route.len);
    constexpr std::size_t k_overhead = k_proxy_mac + k_join_chunk_header;
    if (cap <= k_overhead) {
        finish_out(false, now);
        return;
    }
    const std::size_t chunk = std::min({cap - k_overhead, k_join_chunk_bytes, out_.len - out_.off});
    const std::size_t plain_len = k_overhead + chunk;
    std::array<uint8_t, k_record_max> rec{};
    wire::EndHeader h;
    h.end_sid = delivery::k_tunnel_sid;
    h.end_counter = ++seq_;
    h.app_port = 0;
    h.record_kind = wire::RecordKind::Control;
    h.flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
    h.plaintext_length = static_cast<uint16_t>(plain_len);
    JoinChunk c;
    c.object_id = out_.id;
    c.total = static_cast<uint16_t>(out_.len);
    c.offset = static_cast<uint16_t>(out_.off);
    c.bytes = ByteView{out_.bytes.data() + out_.off, chunk};
    std::size_t clen = 0;
    std::memcpy(rec.data() + wire::k_end_header_bytes, out_.mac.bytes.data(), k_proxy_mac);
    if (wire::encode_end_header(h, MutByteView{rec.data(), wire::k_end_header_bytes}) != Status::Ok ||
        encode_chunk(c, MutByteView{rec.data() + wire::k_end_header_bytes + k_proxy_mac, plain_len - k_proxy_mac},
                     clen) != Status::Ok) {
        finish_out(false, now);
        return;
    }
    const ByteView record{rec.data(), wire::k_end_header_bytes + plain_len + wire::k_tag_bytes};
    out_.inflight = true;
    out_.off += chunk;
    const Status st = engine_.delivery().send_routed(route, record, delivery::OwnerKind::Tunnel, Handle{}, now);
    if (st == Status::NoCapacity || st == Status::Busy) {
        out_.inflight = false; // TX pool full: local, the same chunk is tried again shortly
        out_.off -= chunk;
        retry_at_ = now + k_shortage_retry;
    } else if (st != Status::Ok) {
        out_.inflight = false;
        finish_out(false, now);
    }
}

void Proxy::on_frame_done(const delivery::FrameDone &f, delivery::HopEnd end, MonoTime now) {
    if (f.kind != delivery::OwnerKind::Tunnel || !out_.active || !out_.inflight) {
        return;
    }
    out_.inflight = false;
    if (end != delivery::HopEnd::Accepted) {
        finish_out(false, now); // the next hop refused or never answered: this frame is lost, the joiner repeats
    } else if (out_.off >= out_.len) {
        finish_out(true, now);
    } else {
        pump_out(now);
    }
}

void Proxy::finish_out(bool ok, MonoTime now) {
    const uint32_t tag = out_.tag;
    const bool root_side = is_root();
    if (!ok) {
        ++stats_.lost;
    }
    out_ = Out{};
    if (root_side && tag != 0) {
        outcome_tag_ = tag; // reported after the gap: the caller sends its next fragment only then
        outcome_ok_ = ok;
        outcome_at_ = now + k_down_gap;
    }
}

// ---- receiving tunnel records ----
void Proxy::on_record(const delivery::PathSpec &reply, ByteView plain, MonoTime now) {
    if (!k_proxy_built || plain.size() <= k_proxy_mac) {
        return;
    }
    MacAddr mac;
    std::memcpy(mac.bytes.data(), plain.data(), k_proxy_mac);
    JoinChunk c;
    if (decode_chunk(plain.subspan(k_proxy_mac, plain.size() - k_proxy_mac), c) != Status::Ok || c.ack ||
        c.total > port::k_max_frame_bytes) {
        return;
    }
    Entry *e = find(mac);
    if (e == nullptr) {
        if (!is_root()) {
            return; // a relay only carries frames for joiners it knows
        }
        // A tunnel must never capture the address of a real neighbour: its frames would vanish into the tunnel.
        if (engine_.link().neighbors().find_mac(mac) != nullptr || engine_.link().neighbors().has_grace(mac)) {
            return;
        }
        e = add(mac, now);
        if (e == nullptr) {
            ++stats_.dropped_full;
            return;
        }
    }
    e->last = now;
    if (is_root()) {
        e->proxy_addr = reply.dest.value();
    }
    if (c.offset == 0) {
        if (in_.ready || (in_.active && in_.mac != mac)) {
            ++stats_.dropped_busy; // another frame is being assembled or waits for the radio
            return;
        }
        in_.active = true;
        in_.mac = mac;
        in_.id = c.object_id;
        in_.total = c.total;
        in_.len = 0;
    } else if (!in_.active || in_.mac != mac || in_.id != c.object_id || in_.total != c.total || in_.len != c.offset) {
        return; // out of order: the sender's frame is lost, the joiner repeats
    }
    std::memcpy(in_.bytes.data() + in_.len, c.bytes.data(), c.bytes.size());
    in_.len += c.bytes.size();
    if (in_.len == in_.total) {
        in_.ready = true;
        deliver_in(now);
    }
}

void Proxy::deliver_in(MonoTime now) {
    if (is_root()) { // as if it came from a radio
        port::RadioRx vrx;
        vrx.src = in_.mac;
        vrx.len = static_cast<uint8_t>(in_.len);
        std::memcpy(vrx.bytes.data(), in_.bytes.data(), in_.len);
        in_ = In{};
        ++stats_.up;
        (void)engine_.link().on_rx(vrx, now);
        return;
    }
    const Status st = engine_.transmit(in_.mac, ByteView{in_.bytes.data(), in_.len}, k_tag_proxy, now);
    if (st == Status::Busy || st == Status::DriverResultUnknown) {
        retry_at_ = now + k_shortage_retry; // radio occupied: local, the assembled frame waits
        return;
    }
    in_ = In{};
    ++stats_.down;
}

// ---- root: the join machinery transmits to a joiner's MAC ----
bool Proxy::owns(const MacAddr &mac) const {
    return is_root() && std::any_of(table_.begin(), table_.end(), [&](const Entry &e) { return e.used && e.mac == mac; });
}

Status Proxy::transmit(const MacAddr &mac, ByteView frame, uint32_t tag, MonoTime now) {
    Entry *e = find(mac);
    if (!k_proxy_built || e == nullptr || frame.empty() || frame.size() > k_proxy_frame) {
        return Status::InvalidArgument;
    }
    if (out_.active) {
        return Status::Busy; // one frame in the pipe: the caller's retry timer asks again
    }
    start_out(mac, frame, e->proxy_addr, tag, now, true);
    return Status::Ok;
}

} // namespace lm::member
