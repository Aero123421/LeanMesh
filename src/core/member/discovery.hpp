// Listen-first discovery policy (docs/07 §3), shared by everything that looks for a peer to attach
// to: the joiner's search for a root/proxy (Membership) and a member's search for a parent (Mesh).
// It owns only the timing and the budgets, never a candidate or a frame:
//   1. LISTEN   800 ms without transmitting: a peer that already talks makes a hello unnecessary;
//   2. HELLO    the first hint request after a jitter of 0..400 ms, then every second;
//   3. budget   one search lasts at most 30 s, at most 2 full-handshake candidates are spent;
//   4. BACKOFF  after a spent budget 1 s, doubling to 60 s; the next search starts by itself
//               (auto_resume) or waits for its owner. An explicit request or the node's own authenticated
//               evidence (a lost parent session, a refusal of the root) clears it at once (wake). An
//               unauthenticated hint (a new candidate's beacon, an offer's higher expected revision) only ends a
//               running backoff early, at most once per k_hint_gap for all sources together, and never shortens
//               the backoff that follows (docs/07 §3, docs/21 §3: hints are rate-limited; review finding 1).
// A spent budget or an unexpected device is not a fault (nothing here fails a device). Bounded state,
// no allocation, no polling: `deadline()` is the only timer.
#pragma once

#include <array>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/member/join_wire.hpp"
#include "core/time.hpp"
#include "gen/defaults.hpp"

namespace lm::member {

// ---- SEC-Da: the optional DiscoveryScopeKey (docs/07 §2-§3) ----
// A factory-provisioned 32-byte key shared by the devices, relays and roots of one deployment scope (never a per-
// domain secret). A scoped node tags its hello/offer with HMAC-SHA256(key, "LM1-DISC" || object kind || the hello's
// nonce || offer fields: depth u8, revision u32be), first 8 bytes, and answers/follows only hints with its scope's
// tag. Every holder of the key can make one, so the tag narrows discovery and spares handshakes; it never
// authorises anything (the handshake and the credentials do), and a miss is no verdict on the device.
inline constexpr std::size_t k_scope_key_bytes = 32;
[[nodiscard]] Status scope_tag(ByteView key, uint8_t kind, const std::array<uint8_t, 16> &nonce, const OfferHint &fields,
                               std::array<uint8_t, 8> &tag);
// A hint of `kind` for `nonce` passes the scope filter of a node holding `key` (empty: an unscoped node takes any).
[[nodiscard]] bool scope_ok(ByteView key, uint8_t kind, const std::array<uint8_t, 16> &nonce, const OfferHint &hint);
// Sets the scope tag of an outgoing hint (nothing without a key).
[[nodiscard]] Status scope_sign(ByteView key, uint8_t kind, const std::array<uint8_t, 16> &nonce, OfferHint &hint);

class Discovery {
  public:
    static constexpr Duration k_listen = Duration::from_ms(gen::defaults::join::listen_ms);
    static constexpr Duration k_budget = Duration::from_ms(gen::defaults::join::search_budget_ms);
    static constexpr uint8_t k_full_handshakes = static_cast<uint8_t>(gen::defaults::join::full_handshakes);
    static constexpr Duration k_hello_gap = Duration::from_s(1);
    static constexpr Duration k_backoff_min = Duration::from_s(1);
    static constexpr Duration k_backoff_max = Duration::from_s(60);
    static constexpr Duration k_not_expected_min = Duration::from_s(10);
    static constexpr Duration k_hint_gap = Duration::from_s(60); // one unauthenticated hint acted on per minute

    enum class Act : uint8_t { None, Hello, Exhausted, Resumed };

    // Starts a search now. `jitter_ms` 0..399 (random from the owner) spreads the first hello of nodes
    // that boot together. `listen_first` false: this node was on the air already (no listen).
    void begin(MonoTime now, uint16_t jitter_ms, bool listen_first, Duration budget = k_budget,
               bool auto_resume = false);
    void stop() { *this = Discovery{}; }
    // Runs what is due at `now`. Hello: send one hint request. Exhausted: the budget is spent and a
    // backoff runs. Resumed: the backoff is over and the next search started (auto_resume only).
    [[nodiscard]] Act poll(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;

    [[nodiscard]] bool searching() const { return phase_ == Phase::Listen || phase_ == Phase::Hello; }
    [[nodiscard]] bool in_backoff() const { return phase_ == Phase::Backoff; }
    [[nodiscard]] bool listening(MonoTime now) const { return phase_ == Phase::Listen && now < hello_at_; }
    [[nodiscard]] bool active() const { return phase_ != Phase::Idle; }
    // A full handshake with a candidate may start (the search's budget of two is not spent).
    [[nodiscard]] bool may_handshake() const { return searching() && handshakes_ < k_full_handshakes; }
    void note_handshake() { ++handshakes_; }
    // The owner asks again or has authenticated evidence: the backoff (and a spent handshake budget) is cleared.
    void wake(MonoTime now, uint16_t jitter_ms);
    // An unauthenticated hint. False: the hint period of all sources is not over (ignore the hint). True: it may be
    // acted on; a running backoff ended (the next search starts now; the backoff after it is as long as before).
    [[nodiscard]] bool hint(MonoTime now);
    // The peer refused with "not expected": no hello before `hold` (10..60 s) unless the expected revision
    // advances beyond `revision` (then the owner calls wake()). Not the same timer as the backoff.
    void not_expected(MonoTime now, Duration hold, uint32_t revision) {
        suppress_until_ = now + (hold < k_not_expected_min ? k_not_expected_min : hold);
        refused_revision_ = revision;
        refused_ = true;
    }
    [[nodiscard]] bool revision_advanced(uint32_t revision) const { return refused_ && revision > refused_revision_; }
    [[nodiscard]] bool suppressed(MonoTime now) const { return now < suppress_until_; }
    void clear_suppress() {
        suppress_until_ = MonoTime{0};
        refused_revision_ = 0;
        refused_ = false;
    }
    [[nodiscard]] uint32_t backoff_ms() const { return static_cast<uint32_t>(backoff_.to_ms()); }
    [[nodiscard]] uint8_t handshakes() const { return handshakes_; }

  private:
    enum class Phase : uint8_t { Idle, Listen, Hello, Backoff };
    Phase phase_ = Phase::Idle;
    MonoTime hello_at_ = MonoTime::never(); // Listen: end of the listen; Hello: next hello
    MonoTime budget_end_ = MonoTime::never();
    MonoTime resume_at_ = MonoTime::never();
    MonoTime suppress_until_{};
    Duration budget_ = k_budget;
    Duration backoff_ = k_backoff_min;
    uint32_t refused_revision_ = 0;
    bool refused_ = false;
    uint8_t handshakes_ = 0;
    bool auto_resume_ = false;
    MonoTime hint_at_{}; // the next unauthenticated hint that may be acted on (one bucket for all sources)
};

} // namespace lm::member
