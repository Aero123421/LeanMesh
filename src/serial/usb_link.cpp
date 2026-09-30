#include "serial/usb_link.hpp"

#include <algorithm>
#include <cstring>

#include "core/assert.hpp"
#include "core/codec.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"

namespace lm::serial {
namespace {

constexpr uint8_t k_hello_version = 1;
constexpr uint8_t k_wire_version = 1;

void write_header(uint8_t *out, SerialKind kind, uint32_t sid, uint64_t counter, uint16_t len) {
    Writer w{MutByteView{out, wire::k_serial_header_bytes}};
    w.u8('L');
    w.u8('S');
    w.u8(k_wire_version);
    w.u8(static_cast<uint8_t>(kind));
    w.u32be(sid);
    w.u64be(counter);
    w.u16be(len);
}

Duration hello_delay(const UsbTiming &t, uint32_t tries) {
    if (tries < t.hello_fast_tries) {
        return t.hello_fast;
    }
    const uint32_t shift = std::min<uint32_t>(tries - t.hello_fast_tries + 1, 6);
    return Duration{std::min(t.hello_max.us, t.hello_fast.us << shift)};
}

} // namespace

UsbLink::UsbLink(UsbRole role, UsbEnv &env, UsbSink *sink, uint64_t boot_id, bool auto_release)
    : role_(role), env_(env), sink_(sink), boot_id_(boot_id), auto_release_(auto_release) {}

// ---- lifecycle ----
Status UsbLink::configure(const UsbKit &kit) {
    if (phase_ != Phase::Idle) {
        return Status::Busy;
    }
    if (kit.ccs.size() > sec::k_ccs_max_bytes) {
        return Status::NoCapacity;
    }
    ccs_ = kit.ccs;
    key_ = kit.key;
    trust_ = kit.trust;
    self_ = kit.self;
    domain_ = kit.domain;
    paired_ = kit.paired;
    // Own credential object CBOR [device] (Host) or [device, delegation] (root), written by stage_cred().
    const bool root = role_ == UsbRole::Root;
    if (root && kit.delegation_cose.empty()) {
        return Status::InvalidArgument;
    }
    own_dc_ = kit.device_cose;
    own_deleg_ = root ? kit.delegation_cose : ByteView{};
    if (cred_size() > k_cred_bytes) {
        return Status::NoCapacity;
    }
    LM_TRY(sec::sha256(kit.device_cose, own_hash_));
    configured_ = true;
    return Status::Ok;
}

void UsbLink::open(MonoTime now) {
    if (open_) {
        close();
    }
    open_ = true;
    dec_.reset();
    tx_off_ = tx_len_ = 0;
    hello_tries_ = 0;
    hello_at_ = now;
    hello_due_ = false;
    hello_reply_due_ = false;
    attempt_wanted_ = false;
    next_attempt_at_ = now;
    fail_streak_ = 0;
    retry_at_ = MonoTime::never();
    if (configured_) {
        hello_due_ = true; // first HELLO at once; the schedule continues from on_timer()
        hello_at_ = now + hello_delay(timing_, hello_tries_++);
    }
}

void UsbLink::close() {
    if (act_ >= 0) {
        teardown(UsbDown::Closed, MonoTime{0});
    }
    abort_attempt(Status::Ok, MonoTime{0});
    for (Keys &k : keys_) {
        k.wipe();
    }
    cand_ = -1;
    open_ = false;
    tx_off_ = tx_len_ = 0;
    retry_at_ = MonoTime::never();
    hello_at_ = MonoTime::never();
    job_retry_at_ = MonoTime::never();
    hello_due_ = hello_reply_due_ = ping_due_ = ping_reply_due_ = ping_out_ = false;
    send_blocked_ = false;
}

void UsbLink::teardown(UsbDown why, MonoTime now) {
    if (act_ < 0) {
        return;
    }
    keys_[act_].wipe();
    act_ = -1;
    reset_ledgers();
    ping_due_ = ping_reply_due_ = ping_out_ = false;
    active_peer_ = DeviceId{};
    active_domain_ = DomainId{};
    if (open_) {
        hello_tries_ = 0;
        hello_at_ = now;
        hello_due_ = configured_;
        hello_at_ = now + hello_delay(timing_, hello_tries_++);
    }
    if (sink_ != nullptr) {
        sink_->on_session(false, gen_, why);
    }
}

void UsbLink::reset_ledgers() {
    tx_lane_ = {};
    rx_lane_ = {};
}

void UsbLink::promote(MonoTime now) {
    const int fresh = cand_;
    cand_ = -1;
    if (act_ >= 0) {
        keys_[act_].wipe();
        act_ = -1;
        if (sink_ != nullptr) {
            sink_->on_session(false, gen_, UsbDown::Replaced);
        }
    }
    act_ = fresh;
    ++gen_;
    ++stats_.sessions;
    reset_ledgers();
    active_peer_ = peer_.device;
    active_domain_ = peer_.domain;
    born_ = now;
    last_rx_ = now;
    last_tx_ = now;
    ping_due_ = ping_reply_due_ = false;
    fail_streak_ = 0;
    last_failure_ = Status::Ok;
    // The attempt is over; its scratch (handshake slot, credentials) is already wiped.
    phase_ = Phase::Idle;
    attempt_deadline_ = MonoTime::never();
    hello_due_ = false;
    hello_at_ = MonoTime::never();
    if (sink_ != nullptr) {
        sink_->on_session(true, gen_, UsbDown::Closed);
    }
}

// ---- RX ----
void UsbLink::on_bytes(ByteView bytes, MonoTime now) {
    stats_.rx_bytes += bytes.size();
    for (const uint8_t b : bytes) {
        const CobsDecoder::Result r = dec_.push(b);
        if (r == CobsDecoder::Result::Frame) {
            handle_frame(now);
        } else if (r == CobsDecoder::Result::Bad) {
            ++stats_.rx_cobs_bad;
        }
        if (!open_) {
            break; // handle_frame ended the link
        }
    }
    stats_.rx_overflow = dec_.overflows();
    pump(now);
}

void UsbLink::handle_frame(MonoTime now) {
    const ByteView decoded = dec_.frame();
    wire::SerialHeader h;
    ByteView body;
    const Status st = wire::decode_serial_frame(decoded, h, body);
    if (st != Status::Ok) {
        ++(st == Status::Unsupported ? stats_.rx_unsupported : stats_.rx_bad_frame);
        return;
    }
    ++stats_.rx_frames;
    switch (h.kind) {
    case SerialKind::Hello:
        handle_hello(body, now);
        return;
    case SerialKind::Edhoc:
        handle_edhoc(h.session_id, body, now);
        return;
    default:
        handle_auth(h, decoded.first(wire::k_serial_header_bytes), body, now);
        return;
    }
}

void UsbLink::handle_hello(ByteView payload, MonoTime now) {
    if (!configured_ || wire::cbor_validate(payload) != Status::Ok) {
        return;
    }
    wire::CborReader r{payload};
    (void)r.array(6, 6);
    (void)r.uint_in(k_hello_version, k_hello_version);
    (void)r.bstr(32, 32);
    (void)r.uint_in(0, UINT64_MAX);
    (void)r.uint_in(0, 0xFFFFFFFFULL);
    (void)r.bstr(16, 16);
    const uint64_t peer_active = r.uint_in(0, 0xFFFFFFFFULL);
    if (r.finish() != Status::Ok) {
        return;
    }
    ++stats_.rx_hello;
    if (role_ == UsbRole::Root) {
        hello_reply_due_ = true;
        return;
    }
    // Host: the root says which session it holds. No match (or none) = handshake, while the old
    // session, if any, keeps serving until the new one is confirmed.
    if (act_ < 0 || peer_active != keys_[act_].sid) {
        attempt_wanted_ = true;
        maybe_start_attempt(now);
    }
}

void UsbLink::handle_auth(const wire::SerialHeader &h, ByteView header18, ByteView body, MonoTime now) {
    int slot = -1;
    if (act_ >= 0 && keys_[act_].sid == h.session_id) {
        slot = act_;
    } else if (cand_ >= 0 && keys_[cand_].sid == h.session_id) {
        slot = cand_;
    }
    if (slot < 0) {
        ++stats_.rx_unknown_session; // stale session (reset/replug) or noise: never applied
        return;
    }
    Keys &k = keys_[slot];
    std::array<uint8_t, wire::k_serial_header_bytes + 32> aad{};
    std::memcpy(aad.data(), header18.data(), header18.size());
    std::memcpy(aad.data() + header18.size(), k.ctx_hash.data(), k.ctx_hash.size());
    std::size_t plen = 0;
    sec::ReplayVerdict verdict = sec::ReplayVerdict::Fresh;
    // Decrypted in place: `body` lies in the decode buffer (dec_ -> rx_), which is not read again
    // before this frame is handled, so no second 8 KiB buffer is needed (docs/19 §6).
    LM_ASSERT(body.data() >= rx_.data() && body.data() + body.size() <= rx_.data() + rx_.size());
    const MutByteView sealed{rx_.data() + (body.data() - rx_.data()), body.size()};
    const Status st = k.rec.open_in_place(h.counter, ByteView{aad}, sealed, plen, verdict);
    if (st == Status::Replay && verdict == sec::ReplayVerdict::Duplicate) {
        ++stats_.rx_replay; // authentic duplicate: never applied twice, no reason to end the session
        return;
    }
    if (st != Status::Ok || plen != h.payload_len) {
        ++(st == Status::Replay ? stats_.rx_replay : stats_.rx_auth_fail);
        if (slot == act_) {
            teardown(UsbDown::Aead, now); // docs/19 §5: AEAD/counter mismatch cuts the session
        } else {
            abort_attempt(Status::AuthRejected, now);
        }
        return;
    }
    // FIX11-D5: a USB stream is ordered and CRC-checked, so an authentic record whose counter is not exactly the next
    // one means an earlier record was lost (CRC drop, overflow) or withheld. Its effects (an event the peer believes
    // delivered, the credit of the lost record) are unknown: cut the session and start fresh (docs/19 §5).
    if (h.counter != k.rec.window().highest() + 1) {
        ++stats_.rx_counter_gap;
        if (slot == act_) {
            teardown(UsbDown::Aead, now);
        } else {
            abort_attempt(Status::AuthRejected, now);
        }
        return;
    }
    const ByteView plain{sealed.data(), plen};
    if (slot == cand_) {
        // Key confirmation: the first protected record must be the PING that proves the keys.
        wire::CborReader r{plain};
        std::array<uint8_t, 16> nonce{};
        bool reply = false;
        bool ok = h.kind == SerialKind::Ping && wire::cbor_validate(plain) == Status::Ok;
        if (ok) {
            (void)r.array(2, 2);
            const ByteView n = r.bstr(16, 16);
            reply = r.boolean();
            ok = r.finish() == Status::Ok;
            if (ok) {
                std::copy(n.begin(), n.end(), nonce.begin());
            }
        }
        const bool expected = role_ == UsbRole::Root ? !reply : (reply && ping_out_ && nonce == ping_nonce_);
        if (!ok || !expected) {
            ++stats_.rx_malformed;
            abort_attempt(Status::AuthRejected, now);
            return;
        }
        k.rec.accept(h.counter);
        promote(now);
        if (role_ == UsbRole::Root) {
            ping_reply_nonce_ = nonce;
            ping_reply_due_ = true;
        }
        ping_out_ = false;
        return;
    }
    handle_active(slot, h, plain, static_cast<uint32_t>(header18.size() + body.size() + wire::k_serial_crc_bytes),
                  now);
}

void UsbLink::handle_active(int slot, const wire::SerialHeader &h, ByteView plain,
                            uint32_t frame_bytes, MonoTime now) {
    const SerialKind kind = h.kind;
    if (kind == SerialKind::Ping) {
        wire::CborReader r{plain};
        bool ok = wire::cbor_validate(plain) == Status::Ok;
        if (ok) {
            (void)r.array(2, 2);
            const ByteView n = r.bstr(16, 16);
            const bool reply = r.boolean();
            ok = r.finish() == Status::Ok;
            if (ok) {
                keys_[slot].rec.accept(h.counter);
                note_rx(now);
                ++stats_.pings_rx;
                if (!reply) {
                    std::copy(n.begin(), n.end(), ping_reply_nonce_.begin());
                    ping_reply_due_ = true;
                } else if (ping_out_ && bytes_equal(n, ByteView{ping_nonce_})) {
                    ping_out_ = false;
                }
            }
        }
        if (!ok) {
            ++stats_.rx_malformed;
            teardown(UsbDown::Peer, now);
        }
        return;
    }
    if (kind == SerialKind::Credit) {
        wire::CborReader r{plain};
        bool ok = wire::cbor_validate(plain) == Status::Ok;
        uint64_t lane = 0, frames = 0, bytes = 0;
        if (ok) {
            (void)r.array(3, 3);
            lane = r.uint_in(0, 1);
            frames = r.uint_in(0, UINT64_MAX);
            bytes = r.uint_in(0, UINT64_MAX);
            ok = r.finish() == Status::Ok;
        }
        if (!ok) {
            ++stats_.rx_malformed;
            teardown(UsbDown::Peer, now);
            return;
        }
        TxLane &t = tx_lane_[lane];
        const LaneWindow &w = k_windows[lane];
        // Cumulative grants only grow, never below what was used, never more than one window ahead
        // (this also rejects wrapped values); repeating the same value adds nothing (docs/19 §5).
        if (frames < t.grant_frames || bytes < t.grant_bytes || frames < t.used_frames ||
            bytes < t.used_bytes || frames - t.used_frames > w.frames ||
            bytes - t.used_bytes > w.bytes) {
            ++stats_.rx_credit_violation;
            teardown(UsbDown::Credit, now);
            return;
        }
        keys_[slot].rec.accept(h.counter);
        note_rx(now);
        t.grant_frames = frames;
        t.grant_bytes = bytes;
        if (send_blocked_ && sink_ != nullptr) {
            send_blocked_ = false;
            sink_->on_tx_ready();
        }
        return;
    }
    // REQUEST / RESPONSE / EVENT consume receive credit on their lane.
    const uint8_t lane = lane_of(kind, frame_bytes);
    RxLane &rx = rx_lane_[lane];
    const LaneWindow &w = k_windows[lane];
    if (rx.consumed_frames + 1 - rx.released_frames > w.frames ||
        rx.consumed_bytes + frame_bytes - rx.released_bytes > w.bytes) {
        ++stats_.rx_credit_violation;
        teardown(UsbDown::Credit, now);
        return;
    }
    keys_[slot].rec.accept(h.counter);
    note_rx(now);
    rx.consumed_frames += 1;
    rx.consumed_bytes += frame_bytes;
    if (wire::cbor_validate(plain) != Status::Ok) {
        ++stats_.rx_malformed; // authentic but not deterministic CBOR: refused, credit returned
        release(lane, 1, frame_bytes, now);
        return;
    }
    if (sink_ != nullptr) {
        sink_->on_record(kind, lane, frame_bytes, plain, gen_);
    }
    if (auto_release_) {
        release(lane, 1, frame_bytes, now);
    }
}

void UsbLink::release(uint8_t lane, uint32_t frames, uint32_t bytes, MonoTime now) {
    if (lane > 1 || act_ < 0) {
        return;
    }
    RxLane &rx = rx_lane_[lane];
    // Never release more than was consumed (a caller bug must not mint credit).
    rx.released_frames = std::min<uint64_t>(rx.consumed_frames, rx.released_frames + frames);
    rx.released_bytes = std::min<uint64_t>(rx.consumed_bytes, rx.released_bytes + bytes);
    if (open_) {
        pump(now);
    }
}

uint64_t UsbLink::rx_outstanding_frames(uint8_t lane) const {
    return lane > 1 ? 0 : rx_lane_[lane].consumed_frames - rx_lane_[lane].released_frames;
}

uint64_t UsbLink::tx_available_frames(uint8_t lane) const {
    return lane > 1 ? 0 : tx_lane_[lane].grant_frames - tx_lane_[lane].used_frames;
}

bool UsbLink::tx_room(uint8_t lane, std::size_t decoded) const {
    const TxLane &t = tx_lane_[lane];
    return t.used_frames + 1 <= t.grant_frames && t.used_bytes + decoded <= t.grant_bytes;
}

// ---- TX ----
Status UsbLink::emit(SerialKind kind, uint32_t sid, Keys *keys, ByteView payload, MonoTime now) {
    if (tx_len_ != 0) {
        return Status::Busy;
    }
    const bool auth = wire::serial_kind_authenticated(kind);
    if (auth != (keys != nullptr)) {
        return Status::InvalidArgument;
    }
    if (payload.size() > (auth ? k_plain_bytes : wire::k_serial_unauth_payload_max)) {
        return Status::PayloadTooLarge;
    }
    uint8_t *frame = tx_.data() + k_cobs_headroom;
    const std::size_t body_len = payload.size() + (auth ? sec::k_aead_tag_bytes : 0);
    const std::size_t covered = wire::k_serial_header_bytes + body_len;
    uint64_t counter = 0;
    if (auth) {
        LM_TRY(keys->rec.next_counter(counter));
    }
    // send_built(): the plaintext already stands where the body goes and is sealed in place.
    uint8_t *const body = frame + wire::k_serial_header_bytes;
    const bool in_place = payload.data() == body;
    write_header(frame, kind, sid, counter, static_cast<uint16_t>(payload.size()));
    if (auth) {
        std::array<uint8_t, wire::k_serial_header_bytes + 32> aad{};
        std::memcpy(aad.data(), frame, wire::k_serial_header_bytes);
        std::memcpy(aad.data() + wire::k_serial_header_bytes, keys->ctx_hash.data(), 32);
        LM_TRY(in_place ? keys->rec.seal_in_place(counter, ByteView{aad}, MutByteView{body, body_len})
                        : keys->rec.seal(counter, ByteView{aad}, payload, MutByteView{body, body_len}));
        last_tx_ = now;
    } else if (!payload.empty() && !in_place) {
        std::memcpy(frame + wire::k_serial_header_bytes, payload.data(), payload.size());
    }
    Writer crc{MutByteView{frame + covered, wire::k_serial_crc_bytes}};
    crc.u32be(wire::crc32_iso_hdlc(ByteView{frame, covered}));
    const std::size_t enc =
        cobs_encode_in_place(MutByteView{tx_}, k_cobs_headroom, covered + wire::k_serial_crc_bytes);
    if (enc == 0) {
        return Status::RecoveryRequired; // cannot happen inside the size caps
    }
    tx_len_ = enc;
    tx_off_ = 0;
    ++stats_.tx_frames;
    return Status::Ok;
}

Status UsbLink::emit_control(SerialKind kind, ByteView payload, MonoTime now) {
    return emit(kind, act_ >= 0 ? keys_[act_].sid : 0, act_ >= 0 ? &keys_[act_] : nullptr, payload, now);
}

bool UsbLink::flush(MonoTime now) {
    if (tx_len_ == 0) {
        return true;
    }
    const std::size_t n = env_.write(ByteView{tx_.data() + tx_off_, tx_len_ - tx_off_});
    tx_off_ += n;
    if (tx_off_ >= tx_len_) {
        tx_off_ = tx_len_ = 0;
        retry_at_ = MonoTime::never();
        return true;
    }
    ++stats_.tx_partial; // a slow reader, not a loss: the rest goes out on the next attempt
    retry_at_ = now + timing_.tx_retry;
    return false;
}

bool UsbLink::credit_due(uint8_t lane) const {
    const RxLane &r = rx_lane_[lane];
    const LaneWindow &w = k_windows[lane];
    const uint64_t gf = w.frames + r.released_frames;
    const uint64_t gb = w.bytes + r.released_bytes;
    if (r.sent_frames == 0 && r.sent_bytes == 0) {
        return true; // the session's initial grant
    }
    return gf - r.sent_frames >= std::max<uint32_t>(1, w.frames / 2) ||
           gb - r.sent_bytes >= w.bytes / 2;
}

bool UsbLink::pump_one(MonoTime now) {
    if (!flush(now)) {
        return false;
    }
    std::array<uint8_t, 64> buf{};
    // 1. handshake object
    if (stage_len_ != 0 && !stage_hold_) {
        if (emit(SerialKind::Edhoc, cand_sid_, nullptr, ByteView{stage_.data(), stage_len_}, now) == Status::Ok) {
            stage_len_ = 0;
            return true;
        }
        return false;
    }
    // 2. Host: the key-confirming PING under the candidate keys
    if (bind_ping_due_ && cand_ >= 0) {
        env_.random(MutByteView{ping_nonce_});
        wire::CborWriter w{MutByteView{buf}};
        w.array(2);
        w.bytes(ByteView{ping_nonce_});
        w.boolean(false);
        if (emit(SerialKind::Ping, keys_[cand_].sid, &keys_[cand_], w.written(), now) == Status::Ok) {
            bind_ping_due_ = false;
            ping_out_ = true;
            return true;
        }
        return false;
    }
    if (act_ >= 0) {
        // PING reply first: the peer confirms keys with it before it accepts anything else.
        if (ping_reply_due_) {
            wire::CborWriter w{MutByteView{buf}};
            w.array(2);
            w.bytes(ByteView{ping_reply_nonce_});
            w.boolean(true);
            if (emit_control(SerialKind::Ping, w.written(), now) == Status::Ok) {
                ping_reply_due_ = false;
                return true;
            }
            return false;
        }
        for (uint8_t lane = 0; lane < 2; ++lane) {
            if (!credit_due(lane)) {
                continue;
            }
            RxLane &r = rx_lane_[lane];
            const LaneWindow &win = k_windows[lane];
            const uint64_t gf = win.frames + r.released_frames;
            const uint64_t gb = win.bytes + r.released_bytes;
            wire::CborWriter w{MutByteView{buf}};
            w.array(3);
            w.uint(lane);
            w.uint(gf);
            w.uint(gb);
            if (emit_control(SerialKind::Credit, w.written(), now) == Status::Ok) {
                r.sent_frames = gf;
                r.sent_bytes = gb;
                return true;
            }
            return false;
        }
        if (ping_due_) {
            env_.random(MutByteView{ping_nonce_});
            wire::CborWriter w{MutByteView{buf}};
            w.array(2);
            w.bytes(ByteView{ping_nonce_});
            w.boolean(false);
            if (emit_control(SerialKind::Ping, w.written(), now) == Status::Ok) {
                ping_due_ = false;
                ping_out_ = true;
                return true;
            }
            return false;
        }
    }
    // 3. HELLO (schedule while there is no session, or the answer to the peer's HELLO)
    const bool reply_ok = hello_reply_due_ && now - hello_reply_at_ >= timing_.hello_reply_gate;
    if ((hello_due_ || reply_ok) && configured_) {
        std::array<uint8_t, 96> hb{};
        std::array<uint8_t, 16> nonce{};
        env_.random(MutByteView{nonce});
        wire::CborWriter w{MutByteView{hb}};
        w.array(6);
        w.uint(k_hello_version);
        w.bytes(self_.view());
        w.uint(boot_id_);
        w.uint(k_caps);
        w.bytes(ByteView{nonce});
        w.uint(act_ >= 0 ? keys_[act_].sid : 0);
        if (emit(SerialKind::Hello, 0, nullptr, w.written(), now) == Status::Ok) {
            hello_due_ = false;
            if (reply_ok) {
                hello_reply_due_ = false;
                hello_reply_at_ = now;
            }
            return true;
        }
    }
    return false;
}

void UsbLink::pump(MonoTime now) {
    if (!open_) {
        return;
    }
    for (int i = 0; i < 16 && pump_one(now); ++i) {
    }
    (void)flush(now);
    if (tx_len_ == 0 && send_blocked_ && sink_ != nullptr && act_ >= 0) {
        // Only when the blockage was the TX buffer, not credit (tx_room is re-checked by send()).
        send_blocked_ = false;
        sink_->on_tx_ready();
    }
}

Status UsbLink::send(SerialKind kind, uint32_t gen, ByteView payload, MonoTime now) {
    if (!open_ || act_ < 0 || gen != gen_) {
        return Status::Conflict; // that session is gone: its results are never re-addressed
    }
    if (kind != SerialKind::Request && kind != SerialKind::Response && kind != SerialKind::Event) {
        return Status::InvalidArgument;
    }
    const std::size_t cap = kind == SerialKind::Request ? k_plain_bytes : k_send_max;
    if (payload.size() > cap) {
        return Status::PayloadTooLarge;
    }
    const std::size_t decoded = decoded_size(payload.size());
    const uint8_t lane = lane_of(kind, decoded);
    if (!tx_room(lane, decoded)) {
        ++stats_.tx_credit_blocked;
        send_blocked_ = true;
        return Status::Busy;
    }
    if (tx_len_ != 0 && !flush(now)) {
        send_blocked_ = true;
        return Status::Busy;
    }
    LM_TRY(emit(kind, keys_[act_].sid, &keys_[act_], payload, now));
    tx_lane_[lane].used_frames += 1;
    tx_lane_[lane].used_bytes += decoded;
    pump(now);
    return Status::Ok;
}

Status UsbLink::send_built(SerialKind kind, uint32_t gen, PayloadWriter &w, MonoTime now) {
    if (!open_ || act_ < 0 || gen != gen_) {
        return Status::Conflict;
    }
    if (kind != SerialKind::Response && kind != SerialKind::Event) {
        return Status::InvalidArgument;
    }
    if (tx_len_ != 0 && !flush(now)) {
        send_blocked_ = true;
        return Status::Busy;
    }
    // No credit for even one frame: do not build (the writer may consume state).
    if (tx_available_frames(k_lane_data) == 0 && (kind == SerialKind::Event || tx_available_frames(k_lane_control) == 0)) {
        ++stats_.tx_credit_blocked;
        send_blocked_ = true;
        return Status::Busy;
    }
    uint8_t *const body = tx_.data() + k_cobs_headroom + wire::k_serial_header_bytes;
    std::size_t len = 0;
    LM_TRY(w.write(MutByteView{body, k_send_max}, len));
    const std::size_t decoded = decoded_size(len);
    const uint8_t lane = lane_of(kind, decoded);
    if (!tx_room(lane, decoded)) {
        ++stats_.tx_credit_blocked;
        send_blocked_ = true;
        return Status::Busy; // the writer's state is unchanged or remembered: it builds again
    }
    LM_TRY(emit(kind, keys_[act_].sid, &keys_[act_], ByteView{body, len}, now));
    tx_lane_[lane].used_frames += 1;
    tx_lane_[lane].used_bytes += decoded;
    pump(now);
    return Status::Ok;
}

// ---- timers ----
MonoTime UsbLink::deadline() const {
    if (!open_) {
        return MonoTime::never();
    }
    MonoTime d = earliest(retry_at_, job_retry_at_);
    if (phase_ != Phase::Idle && phase_ != Phase::Zombie) {
        d = earliest(d, attempt_deadline_);
    }
    if (act_ >= 0) {
        d = earliest(d, last_tx_ + timing_.ping_period);
        d = earliest(d, last_rx_ + timing_.silence);
        d = earliest(d, born_ + (role_ == UsbRole::Host ? timing_.key_rotate : timing_.key_lifetime));
    } else if (configured_) {
        d = earliest(d, hello_at_);
    }
    if (hello_reply_due_) {
        d = earliest(d, hello_reply_at_ + timing_.hello_reply_gate);
    }
    if (attempt_wanted_ && phase_ == Phase::Idle) {
        d = earliest(d, next_attempt_at_);
    }
    return d;
}

void UsbLink::on_timer(MonoTime now) {
    if (!open_) {
        return;
    }
    if (slot_wait_ && now >= job_retry_at_) {
        slot_wait_ = false;
        job_retry_at_ = MonoTime::never();
        after_verify(now); // asks for the slot again (and waits again while it is taken)
    }
    if (job_deferred_ && now >= job_retry_at_) {
        retry_job(now);
    }
    if (phase_ != Phase::Idle && phase_ != Phase::Zombie && now >= attempt_deadline_) {
        abort_attempt(Status::Expired, now);
    }
    if (act_ >= 0) {
        if (now - last_rx_ >= timing_.silence) {
            teardown(UsbDown::Silence, now);
        } else if (now - born_ >= timing_.key_lifetime) {
            teardown(UsbDown::Expired, now);
        } else {
            if (now - last_tx_ >= timing_.ping_period && !ping_due_) {
                ping_due_ = true;
            }
            if (role_ == UsbRole::Host && now - born_ >= timing_.key_rotate) {
                attempt_wanted_ = true; // fresh handshake under the old session (docs/06 §7)
            }
        }
    }
    if (act_ < 0 && configured_ && now >= hello_at_) {
        hello_due_ = true;
        hello_at_ = now + hello_delay(timing_, hello_tries_++);
    }
    maybe_start_attempt(now);
    pump(now);
}

} // namespace lm::serial
