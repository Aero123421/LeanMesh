// POWER poll/grant (docs/20 §3) and the parent's mailbox (docs/20 §5, docs/22 §5).
// Device side: one authenticated poll per episode to the approved parent; a lost GRANT is asked for again with the
// same nonce (at most `poll_max_attempts` tries, the window is never extended by a retry).
// Parent side: a child that polled is awake until the window of its *first* poll ends; frames for it that arrive
// while it sleeps stay in the TX pool, unsent (`deliverable()`), and go out within the credit it asked for.
#include "core/engine.hpp"
#include "core/power/power.hpp"

namespace lm::power {
namespace {

constexpr Duration k_grant_retry = Duration::from_ms(20);   // radio busy: the grant is owed, look again shortly
constexpr Duration k_poll_gap_min = Duration::from_ms(20);  // a child cannot poll faster (fresh nonces)
constexpr uint32_t k_window_cap_ms = 60000;
constexpr uint32_t k_hold_min_ms = 10000;
constexpr uint32_t k_hold_max_ms = 7200000;
constexpr uint32_t k_stale_min_ms = 60000;
constexpr uint8_t k_grant_no_capacity = 1;
constexpr uint32_t k_poll_attempts = gen::defaults::power_limits::poll_max_attempts;

uint32_t hold_ms(uint32_t interval_ms, uint32_t window_ms) {
    const uint64_t h = interval_ms == 0 ? 60000ULL : 2ULL * interval_ms + window_ms;
    return static_cast<uint32_t>(std::min<uint64_t>(std::max<uint64_t>(h, k_hold_min_ms), k_hold_max_ms));
}
Duration stale_after(const uint32_t interval_ms) {
    return Duration::from_ms(std::max<uint64_t>(k_stale_min_ms, 3ULL * interval_ms));
}

} // namespace

// ---- device side ------------------------------------------------------------------------------------
void Power::on_parent_ready(MonoTime now) {
    if (sleepy_mode() && poll_.want && !poll_.granted && poll_.attempts == 0 && !asleep()) {
        send_poll(now);
    }
}

void Power::send_poll(MonoTime now) {
    MacAddr mac;
    DeviceId dev;
    if (!engine_.mesh().parent_link(mac, dev)) {
        return; // no authenticated parent link: nothing to poll (an unauthenticated poll proves nothing)
    }
    poll_mac_ = mac;
    if (poll_.attempts == 0) { // the first poll of the chain fixes nonce, credit and window
        std::array<uint8_t, 8> r{};
        engine_.random(MutByteView{r});
        for (uint8_t b : r) {
            poll_.nonce = poll_.nonce << 8U | b;
        }
        poll_.nonce |= 1U; // never 0
        poll_.first = now;
        poll_.window_ms = static_cast<uint16_t>(std::min<uint32_t>(policy_.rx_window_ms, 0xFFFF));
        poll_.credit = static_cast<uint16_t>(std::min<std::size_t>(policy_.mailbox_child, engine_.delivery().hop().free_frames()));
        window_end_ = now + Duration::from_ms(poll_.window_ms);
        window_closed_ = false;
        if (cont_start_.is_never()) {
            cont_start_ = now;
        }
    }
    wire::PowerPoll p;
    p.rx_credit = poll_.credit;
    p.poll_nonce = poll_.nonce;
    p.revision_hint = static_cast<uint32_t>(policy_.revision);
    const uint64_t planned = cur_.sleep_ms != 0 ? cur_.sleep_ms : policy_.wake_interval_ms;
    p.planned_interval_ms = static_cast<uint32_t>(std::min<uint64_t>(planned, 86400000U));
    p.window_ms = poll_.window_ms == 0 ? 1 : poll_.window_ms;
    std::array<uint8_t, wire::k_max_frame_bytes> plain{};
    std::size_t len = 0;
    Status st = engine_.tx().in_flight() ? Status::Busy : wire::encode_power_poll(p, MutByteView{plain}, len);
    if (st == Status::Ok) {
        st = engine_.link().send_sealed(dev, mac, wire::FrameKind::Power, ByteView{plain.data(), len}, k_tag_power, now);
    }
    if (st == Status::Busy || st == Status::DriverResultUnknown) {
        poll_.retry = now + k_grant_retry; // the radio is occupied: local, neither an attempt nor a loss
        return;
    }
    if (st != Status::Ok) {
        poll_.want = false; // no session to seal with: the attach path re-establishes it, then polls again
        poll_.attempts = 0;
        poll_.retry = MonoTime::never();
        return;
    }
    ++poll_.attempts;
    ++stats_.polls;
    const Duration gap = Duration::from_ms(std::clamp<uint32_t>(poll_.window_ms / 3U, 20, 200));
    const MonoTime next = now + gap;
    poll_.retry = poll_.attempts < k_poll_attempts && next < poll_.first + Duration::from_ms(poll_.window_ms)
                      ? next
                      : poll_.first + Duration::from_ms(poll_.window_ms);
}

void Power::poll_timer(MonoTime now) {
    if (!poll_.want || poll_.granted || poll_.retry.is_never() || now < poll_.retry) {
        return;
    }
    if (poll_.attempts >= k_poll_attempts || now >= poll_.first + Duration::from_ms(poll_.window_ms)) {
        ++stats_.missed_windows; // no GRANT: the parent has probably lost the session, not necessarily the radio
        poll_ = Poll{};
        poll_.want = true; // the poll of this episode is repeated once the session exists again
        engine_.mesh().parent_session_lost(poll_mac_, now);
        return;
    }
    send_poll(now);
}

void Power::on_grant(const wire::PowerGrant &g, MonoTime now) {
    wire::PowerPoll sent;
    sent.rx_credit = poll_.credit;
    sent.poll_nonce = poll_.nonce;
    sent.window_ms = poll_.window_ms;
    if (!poll_.want || poll_.granted || poll_.attempts == 0 || wire::check_grant_against_poll(sent, g) != Status::Ok) {
        return; // a duplicate, a late answer to an older poll, or one that exceeds what we asked for
    }
    poll_.granted = true;
    poll_.retry = MonoTime::never();
    poll_.pending_more = g.pending_frames > g.granted_credit ? static_cast<uint16_t>(g.pending_frames - g.granted_credit) : 0;
    ++stats_.grants;
    window_end_ = poll_.first + Duration::from_ms(g.window_ttl_ms);
    window_closed_ = now >= window_end_;
}

// More frames wait at the parent than one window could take: ask again while the continuous limit allows.
bool Power::continue_poll(MonoTime now) {
    if (!poll_.granted || poll_.pending_more == 0 || ep_over_ || cont_start_.is_never() ||
        now + Duration::from_ms(policy_.rx_window_ms) > cont_start_ + Duration::from_ms(policy_.max_rx_window_ms)) {
        return false;
    }
    poll_ = Poll{};
    poll_.want = true;
    send_poll(now);
    return true;
}

void Power::on_frame(const link::RxInfo &info, ByteView plain, MonoTime now) {
    if (info.duplicate) {
        return; // an authentic repeat of a frame already taken (or replayed): it opens no window and grants nothing
    }
    switch (wire::power_subtype(plain)) {
    case wire::k_power_poll_subtype: {
        wire::PowerPoll p;
        if (wire::decode_power_poll(plain, p) == Status::Ok) {
            on_poll(info, p, now);
        }
        break;
    }
    case wire::k_power_grant_subtype: {
        wire::PowerGrant g;
        if (wire::decode_power_grant(plain, g) == Status::Ok) {
            on_grant(g, now);
        }
        break;
    }
    default:
        break; // unknown subtype: nothing happens (docs/09: unknown POWER content is rejected, never guessed)
    }
}

// ---- parent side ------------------------------------------------------------------------------------
Power::Child *Power::find_child(const MacAddr &mac, MonoTime now) {
    for (Child &c : children_) {
        if (c.used && c.mac == mac) {
            if (now > c.last_poll + stale_after(c.interval_ms)) { // it stopped polling: not a sleepy child any more
                c = Child{};
                return nullptr;
            }
            return &c;
        }
    }
    return nullptr;
}

const Power::Child *Power::find_child(const MacAddr &mac, MonoTime now) const {
    for (const Child &c : children_) {
        if (c.used && c.mac == mac) {
            return now > c.last_poll + stale_after(c.interval_ms) ? nullptr : &c;
        }
    }
    return nullptr;
}

bool Power::child_known(const MacAddr &mac, MonoTime now) const { return find_child(mac, now) != nullptr; }

bool Power::child_awake(const Child &c, MonoTime now) const {
    if (now < c.awake_until) {
        return true;
    }
    const link::Neighbor *nb = engine_.link().neighbors().find_mac(c.mac);
    return nb != nullptr && nb->cur.active && nb->cur.born > c.last_poll;
}

bool Power::child_asleep(const MacAddr &mac, MonoTime now) const {
    const Child *c = find_child(mac, now);
    return c != nullptr && !child_awake(*c, now);
}

bool Power::deliverable(const MacAddr &mac, MonoTime now, bool first_send) const {
    const Child *c = find_child(mac, now);
    if (c == nullptr) {
        return true;
    }
    if (now >= c->awake_until && child_awake(*c, now)) {
        return true; // a session newer than its last poll: no window, no credit, no waiting
    }
    return now + Duration::from_ms(policy_.guard_ms) < c->awake_until && (!first_send || c->credit_left != 0);
}

void Power::on_child_frame(const MacAddr &mac, MonoTime now) {
    Child *c = find_child(mac, now);
    if (c == nullptr) {
        return;
    }
    const MonoTime open = now + Duration::from_ms(c->window_ms);
    if (c->awake_until < open) {
        c->awake_until = open;
        c->credit_left = std::max(c->credit_left, c->credit_req);
    }
}

void Power::note_handoff(const MacAddr &mac) {
    Child *c = find_child(mac, engine_.step_time());
    if (c != nullptr && c->credit_left != 0) {
        --c->credit_left;
    }
}

// docs/20 §5: the mailbox is the shared TX pool; a sleeping child may hold `mailbox_frames_per_child` frames and
// all children together `mailbox_frames_total`. Refusal is credit 0 / NO_CAPACITY towards the sender (BUSY).
bool Power::mailbox_admit(const MacAddr &mac, MonoTime now) {
    Child *c = find_child(mac, now);
    if (c == nullptr || child_awake(*c, now)) {
        return true;
    }
    const delivery::HopTx &hop = engine_.delivery().hop();
    std::size_t total = 0;
    for (const Child &o : children_) {
        total += o.used && !child_awake(o, now) ? hop.queued_for(o.mac) : 0U;
    }
    if (hop.queued_for(mac) >= policy_.mailbox_child || total >= policy_.mailbox_total) {
        return false;
    }
    if (c->hold_until.is_never()) {
        c->hold_until = now + Duration::from_ms(hold_ms(c->interval_ms, c->window_ms));
    }
    return true;
}

bool Power::send_grant(Child &c, uint32_t ttl_ms, uint32_t reason, MonoTime now) {
    if (engine_.tx().in_flight()) {
        return false;
    }
    wire::PowerGrant g;
    g.pending_frames = static_cast<uint16_t>(std::min<std::size_t>(engine_.delivery().hop().queued_for(c.mac), 0xFFFF));
    g.poll_nonce = c.nonce;
    g.window_ttl_ms = std::clamp<uint32_t>(ttl_ms, 1, 0xFFFF);
    g.granted_credit = c.granted;
    g.reason = reason;
    std::array<uint8_t, wire::k_max_frame_bytes> plain{};
    std::size_t len = 0;
    const link::Neighbor *nb = engine_.link().neighbors().find_mac(c.mac);
    Status st = nb == nullptr ? Status::AuthPending : wire::encode_power_grant(g, MutByteView{plain}, len);
    if (st == Status::Ok) {
        st = engine_.link().send_sealed(nb->device, c.mac, wire::FrameKind::Power, ByteView{plain.data(), len},
                                        k_tag_power, now);
    }
    if (st == Status::Ok) {
        ++stats_.polls_served;
    }
    return st != Status::Busy && st != Status::DriverResultUnknown;
}

void Power::on_poll(const link::RxInfo &info, const wire::PowerPoll &p, MonoTime now) {
    if (k_children == 0 || engine_.config().role == Role::Leaf) {
        return; // a leaf does not serve: sleepy devices never relay (docs/13 §1)
    }
    Child *c = find_child(info.src, now);
    if (c != nullptr && c->nonce == p.poll_nonce) { // the GRANT was lost: answer again, same window, same credit
        if (!send_grant(*c, static_cast<uint32_t>((c->first_poll + Duration::from_ms(c->window_ms) - now).to_ms()), 0, now)) {
            c->grant_due = true;
            c->grant_at = now + k_grant_retry;
        }
        return;
    }
    if (c != nullptr && now - c->last_poll < k_poll_gap_min) {
        ++stats_.polls_refused; // a child cannot open windows faster than this
        return;
    }
    if (c == nullptr) {
        for (Child &slot : children_) {
            if (!slot.used) {
                c = &slot;
                break;
            }
        }
    }
    if (c == nullptr) { // table full: an explicit refusal (credit 0), not silence
        Child tmp;
        tmp.mac = info.src;
        tmp.nonce = p.poll_nonce;
        ++stats_.polls_refused;
        (void)send_grant(tmp, 1, k_grant_no_capacity, now);
        return;
    }
    const std::size_t pending = engine_.delivery().hop().queued_for(info.src);
    c->used = true;
    c->mac = info.src;
    c->nonce = p.poll_nonce;
    c->first_poll = c->last_poll = now;
    c->window_ms = static_cast<uint16_t>(std::min<uint32_t>(p.window_ms, k_window_cap_ms));
    c->interval_ms = p.planned_interval_ms;
    c->awake_until = now + Duration::from_ms(c->window_ms);
    c->credit_req = p.rx_credit;
    c->granted = static_cast<uint16_t>(std::min<std::size_t>(p.rx_credit, pending));
    c->credit_left = c->granted;
    if (pending <= c->granted) {
        c->hold_until = MonoTime::never(); // nothing stays parked
    }
    if (!send_grant(*c, c->window_ms, 0, now)) {
        c->grant_due = true;
        c->grant_at = now + k_grant_retry;
    }
    engine_.delivery().hop().pump(now); // the parked frames go out, inside the window
}

void Power::flush_grants(MonoTime now) {
    for (Child &c : children_) {
        if (!c.used || !c.grant_due || now < c.grant_at) {
            continue;
        }
        const MonoTime end = c.first_poll + Duration::from_ms(c.window_ms);
        if (now >= end) {
            c.grant_due = false; // the window is over: the child asks again with a new poll
        } else if (send_grant(c, static_cast<uint32_t>((end - now).to_ms()), 0, now)) {
            c.grant_due = false;
        } else {
            c.grant_at = now + k_grant_retry;
        }
    }
}

// Parked frames whose child never came back: released after the hold time, which tells their owner (a relay's
// forward, a receipt) to give up. The origin still has the original and sends it again (docs/20 §5).
void Power::expire_mailboxes(MonoTime now) {
    for (Child &c : children_) {
        if (!c.used) {
            continue;
        }
        if (!c.hold_until.is_never() && now >= c.hold_until) {
            stats_.parked_expired += engine_.delivery().hop().expire_parked(c.mac, now);
            c.hold_until = MonoTime::never();
        }
        if (now > c.last_poll + stale_after(c.interval_ms) && engine_.delivery().hop().queued_for(c.mac) == 0) {
            c = Child{};
        }
    }
}

} // namespace lm::power
