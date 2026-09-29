// CRYPTO slice (T03) acceptance: record layer, session context, identity/COSE, and the EDHOC
// method-0/suite-3 handshake driven through its job bodies. Vectors: tests/golden.json (AES-GCM
// frames, COSE_Sign1), RFC 9529 chapter 3 (via edhoc_rfc9529.c). Every private key used here is
// generated at run time inside PSA; the only fixed scalar is the public golden test value 1.
// Software-model evidence only: no RF, no target timing, no key-custody review.
#include <malloc.h>
#include <pthread.h>
#include <sys/mman.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <type_traits>
#include <utility>
#include <vector>

#include <psa/crypto.h>

#include "core/codec.hpp"
#include "core/jobs.hpp"
#include "core/ports.hpp"
#include "gen/golden.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_store.hpp"
#include "security/cose_sign1.hpp"
#include "security/crypto.hpp"
#include "security/handshake.hpp"
#include "security/identity.hpp"
#include "security/record.hpp"

extern "C" int lm_test_rfc9529_chapter3(char *why, size_t why_cap);
extern "C" int lm_security_link_check(void); // the on-target gate app runs the same function

// ---- PSA fault injection (linker --wrap, tests/native/CMakeLists.txt) --------------------------------
// A failed destroy does NOT call the real function (the key stays live, like a driver fault); the id
// is remembered so the test can release it afterwards and the heap baseline holds.
extern "C" {
psa_status_t __real_psa_destroy_key(psa_key_id_t);
psa_status_t __real_psa_hash_update(psa_hash_operation_t *, const uint8_t *, size_t);
}
namespace {
int g_destroy_failures = 0;
bool g_hash_update_fails = false;
std::vector<psa_key_id_t> g_stuck_ids;
void release_stuck() {
    g_destroy_failures = 0;
    for (psa_key_id_t id : g_stuck_ids) {
        (void)__real_psa_destroy_key(id);
    }
    g_stuck_ids.clear();
}
} // namespace
extern "C" psa_status_t __wrap_psa_destroy_key(psa_key_id_t id) {
    if (g_destroy_failures > 0) {
        --g_destroy_failures;
        g_stuck_ids.push_back(id);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    return __real_psa_destroy_key(id);
}
extern "C" psa_status_t __wrap_psa_hash_update(psa_hash_operation_t *op, const uint8_t *in, size_t n) {
    return g_hash_update_fails ? PSA_ERROR_HARDWARE_FAILURE : __real_psa_hash_update(op, in, n);
}

// ---- heap accounting (linker --wrap) ---------------------------------------------------------------
// Counts every allocation of the process, which during a handshake is PSA's key slots and bignum
// scratch (first-party code does not allocate after init). Used for the peak and for leak checks.
// Off under the sanitizers (their allocator interposition and --wrap do not combine): the checks
// that depend on it are skipped there and the measurement prints n/a.
#ifdef LM_TEST_HEAP_WRAP
constexpr bool k_heap_accounting = true;
#else
constexpr bool k_heap_accounting = false;
#endif
#define LM_CHECK_HEAP_EQ(a, b)                                                                     \
    do {                                                                                           \
        if (k_heap_accounting) {                                                                   \
            LM_CHECK_EQ(a, b);                                                                     \
        }                                                                                          \
    } while (0)
#ifdef LM_TEST_HEAP_WRAP
extern "C" {
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);
}
namespace {
size_t g_live = 0;
size_t g_peak = 0;
void track_add(void *p) {
    if (p != nullptr) {
        g_live += malloc_usable_size(p);
        g_peak = g_live > g_peak ? g_live : g_peak;
    }
}
void track_sub(void *p) {
    if (p != nullptr) {
        g_live -= malloc_usable_size(p);
    }
}
} // namespace
extern "C" {
void *__wrap_malloc(size_t n) {
    void *p = __real_malloc(n);
    track_add(p);
    return p;
}
void *__wrap_calloc(size_t a, size_t b) {
    void *p = __real_calloc(a, b);
    track_add(p);
    return p;
}
void *__wrap_realloc(void *old, size_t n) {
    track_sub(old);
    void *p = __real_realloc(old, n);
    track_add(p != nullptr ? p : old); // a failed realloc leaves `old` alive
    return p;
}
void __wrap_free(void *p) {
    track_sub(p);
    __real_free(p);
}
}
#else
namespace {
size_t g_live = 0;
size_t g_peak = 0;
} // namespace
#endif

using namespace lm;
using namespace lm::sec;
using Bytes = std::vector<uint8_t>;

namespace {

ByteView view(const Bytes &b) { return ByteView{b.data(), b.size()}; }
template <std::size_t N> ByteView view(const std::array<uint8_t, N> &a) { return ByteView{a.data(), N}; }
Bytes hex(const char *h) { return lmtest::from_hex(h); }

Sha256Digest sha(ByteView in) {
    Sha256Digest d{};
    LM_CHECK_OK(sha256(in, d));
    return d;
}

// ---- golden context parsing --------------------------------------------------------------------
// ["LM1", purpose, fleet16, domain16, dev_i32, dev_r32, gen x4, cred_hash_i, cred_hash_r]
SessionContext parse_golden_context(const Bytes &c) {
    Reader r{view(c)};
    LM_CHECK_EQ(r.u8(), 0x8Cu);
    LM_CHECK_EQ(r.u32be(), 0x634C4D31u); // text(3) "LM1"
    SessionContext s;
    s.purpose = static_cast<Purpose>(r.u8());
    LM_CHECK_EQ(r.u8(), 0x50u);
    r.copy_to(s.fleet.bytes);
    LM_CHECK_EQ(r.u8(), 0x50u);
    r.copy_to(s.domain.bytes);
    LM_CHECK_EQ(r.u16be(), 0x5820u);
    r.copy_to(s.initiator.bytes);
    LM_CHECK_EQ(r.u16be(), 0x5820u);
    r.copy_to(s.responder.bytes);
    s.assignment_i = AssignmentGen{r.u8()};
    s.assignment_r = AssignmentGen{r.u8()};
    s.membership_i = MembershipGen{r.u8()};
    s.membership_r = MembershipGen{r.u8()};
    LM_CHECK_EQ(r.u16be(), 0x5820u);
    r.copy_to(s.credential_hash_i);
    LM_CHECK_EQ(r.u16be(), 0x5820u);
    r.copy_to(s.credential_hash_r);
    LM_CHECK_OK(r.finish());
    return s;
}

// ---- keys for a pair of sessions from a fixed seed (test seed, never a product path) ------------------
void make_pair(const Bytes &seed, const SessionContext &ctx, Purpose purpose, RecordSession &a,
               RecordSession &b, Sha256Digest &h) {
    SessionContext c = ctx;
    c.purpose = purpose;
    LM_CHECK_OK(context_hash(c, h));
    RecordKeys ka, kb;
    LM_CHECK_OK(derive_record_keys(view(seed), h, purpose, true, ka));
    LM_CHECK_OK(derive_record_keys(view(seed), h, purpose, false, kb));
    LM_CHECK_OK(a.install(std::move(ka)));
    LM_CHECK_OK(b.install(std::move(kb)));
}

SessionContext base_context() {
    SessionContext c;
    for (std::size_t i = 0; i < 16; ++i) {
        c.fleet.bytes[i] = static_cast<uint8_t>(0x10 + i);
        c.domain.bytes[i] = static_cast<uint8_t>(0x20 + i);
    }
    c.initiator.bytes.fill(0xA1);
    c.responder.bytes.fill(0xB2);
    c.assignment_i = AssignmentGen{3};
    c.assignment_r = AssignmentGen{4};
    c.membership_i = MembershipGen{5};
    c.membership_r = MembershipGen{6};
    c.credential_hash_i.fill(0xC3);
    c.credential_hash_r.fill(0xD4);
    return c;
}

Bytes seal_bytes(RecordSession &s, ByteView aad, const Bytes &pt, uint64_t &counter) {
    LM_CHECK_OK(s.next_counter(counter));
    Bytes out(pt.size() + 16);
    LM_CHECK_OK(s.seal(counter, aad, view(pt), MutByteView{out.data(), out.size()}));
    return out;
}

Status open_bytes(RecordSession &s, uint64_t counter, ByteView aad, const Bytes &ct, Bytes &pt,
                  ReplayVerdict &v) {
    pt.assign(ct.size() >= 16 ? ct.size() - 16 : 0, 0);
    std::size_t len = 0;
    const Status st = s.open(counter, aad, view(ct), MutByteView{pt.data(), pt.size()}, len, v);
    pt.resize(len);
    return st;
}

} // namespace

// ================================ record layer ===============================================

LM_TEST("S04 record layer reproduces every golden frame byte-exact and opens it") {
    LM_CHECK_OK(crypto_init());
    for (const auto &f : gen::golden::k_frames) {
        const Bytes packet = hex(f.packet_hex);
        const Bytes link_ctx = hex(f.link_context_hex);
        const Bytes end_ctx = hex(f.end_context_hex);

        // The context encoder reproduces the golden context bytes from the parsed fields.
        std::array<uint8_t, k_session_context_max_bytes> enc{};
        std::size_t enc_len = 0;
        const SessionContext lc = parse_golden_context(link_ctx);
        const SessionContext ec = parse_golden_context(end_ctx);
        LM_CHECK_EQ(static_cast<unsigned>(lc.purpose), 1u);
        LM_CHECK_EQ(static_cast<unsigned>(ec.purpose), 2u);
        LM_CHECK_OK(context_encode(lc, MutByteView{enc.data(), enc.size()}, enc_len));
        LM_CHECK(Bytes(enc.begin(), enc.begin() + static_cast<long>(enc_len)) == link_ctx);
        LM_CHECK_OK(context_encode(ec, MutByteView{enc.data(), enc.size()}, enc_len));
        LM_CHECK(Bytes(enc.begin(), enc.begin() + static_cast<long>(enc_len)) == end_ctx);

        RecordSession link_tx, link_rx, end_tx, end_rx;
        Sha256Digest link_h{}, end_h{};
        LM_CHECK_OK(context_hash(lc, link_h));
        LM_CHECK_OK(context_hash(ec, end_h));
        LM_CHECK(link_h == sha(view(link_ctx)));
        RecordKeys k;
        const Bytes link_seed = hex(f.link_exporter_test_seed_hex);
        const Bytes end_seed = hex(f.end_exporter_test_seed_hex);
        LM_CHECK_OK(derive_record_keys(view(link_seed), link_h, Purpose::Link, true, k));
        LM_CHECK_OK(link_tx.install(std::move(k)));
        LM_CHECK_OK(derive_record_keys(view(link_seed), link_h, Purpose::Link, false, k));
        LM_CHECK_OK(link_rx.install(std::move(k)));
        LM_CHECK_OK(derive_record_keys(view(end_seed), end_h, Purpose::End, true, k));
        LM_CHECK_OK(end_tx.install(std::move(k)));
        LM_CHECK_OK(derive_record_keys(view(end_seed), end_h, Purpose::End, false, k));
        LM_CHECK_OK(end_rx.install(std::move(k)));

        // Open both layers.
        LM_CHECK_EQ(packet.size(), 250u);
        const Bytes header(packet.begin(), packet.begin() + 24);
        Reader hr{view(header)};
        (void)hr.bytes(12);
        const uint64_t link_counter = hr.u64be();
        std::array<uint8_t, k_link_aad_bytes> laad{};
        LM_CHECK_OK(link_aad(view(header), link_h, laad));
        Bytes plain;
        ReplayVerdict verdict{};
        LM_CHECK_OK(open_bytes(link_rx, link_counter, view(laad),
                               Bytes(packet.begin() + 24, packet.end()), plain, verdict));
        LM_CHECK(verdict == ReplayVerdict::Fresh);
        const std::size_t off = 16 + 2U * plain[4];
        const Bytes route_and_path(plain.begin(), plain.begin() + static_cast<long>(off));
        const Bytes end_header(plain.begin() + static_cast<long>(off),
                               plain.begin() + static_cast<long>(off) + 42);
        const Bytes end_ct(plain.begin() + static_cast<long>(off) + 42, plain.end());
        Reader rr{view(route_and_path)};
        (void)rr.bytes(8);
        const RootTerm term{rr.u32be()};
        Reader er{view(end_header)};
        (void)er.u32be();
        const uint64_t end_counter = er.u64be();
        std::array<uint8_t, k_end_aad_bytes> eaad{};
        LM_CHECK_OK(end_aad(end_h, term, view(end_header), eaad));
        Bytes payload;
        LM_CHECK_OK(open_bytes(end_rx, end_counter, view(eaad), end_ct, payload, verdict));
        LM_CHECK(payload == hex(f.payload_hex));
        LM_CHECK_EQ(payload.size(), 136u - 2u * f.hops);

        // Re-seal from the seeds: identical ciphertext at both layers.
        uint64_t c = 0;
        while (end_counter > end_tx.tx_used()) {
            LM_CHECK_OK(end_tx.next_counter(c));
        }
        LM_CHECK_EQ(c, end_counter);
        Bytes end_out(payload.size() + 16);
        LM_CHECK_OK(end_tx.seal(end_counter, view(eaad), view(payload),
                                MutByteView{end_out.data(), end_out.size()}));
        LM_CHECK(end_out == end_ct);
        Bytes body = route_and_path;
        body.insert(body.end(), end_header.begin(), end_header.end());
        body.insert(body.end(), end_out.begin(), end_out.end());
        while (link_counter > link_tx.tx_used()) {
            LM_CHECK_OK(link_tx.next_counter(c));
        }
        Bytes link_out(body.size() + 16);
        LM_CHECK_OK(link_tx.seal(link_counter, view(laad), view(body),
                                 MutByteView{link_out.data(), link_out.size()}));
        Bytes rebuilt = header;
        rebuilt.insert(rebuilt.end(), link_out.begin(), link_out.end());
        LM_CHECK(rebuilt == packet);
        LM_CHECK(sha(view(rebuilt)) == sha(view(packet)));

        // Header, ctx_hash, counter and tag changes are all rejected, and none consumes the window.
        Bytes bad_header = header;
        bad_header[4] ^= 1U;
        std::array<uint8_t, k_link_aad_bytes> bad_aad{};
        LM_CHECK_OK(link_aad(view(bad_header), link_h, bad_aad));
        const Bytes link_ct(packet.begin() + 24, packet.end());
        RecordSession fresh_rx;
        LM_CHECK_OK(derive_record_keys(view(link_seed), link_h, Purpose::Link, false, k));
        LM_CHECK_OK(fresh_rx.install(std::move(k)));
        LM_CHECK(open_bytes(fresh_rx, link_counter, view(bad_aad), link_ct, plain, verdict) ==
                 Status::AuthRejected);
        Sha256Digest other = link_h;
        other[0] ^= 1U;
        LM_CHECK_OK(link_aad(view(header), other, bad_aad));
        LM_CHECK(open_bytes(fresh_rx, link_counter, view(bad_aad), link_ct, plain, verdict) ==
                 Status::AuthRejected);
        LM_CHECK(open_bytes(fresh_rx, link_counter + 1, view(laad), link_ct, plain, verdict) ==
                 Status::AuthRejected); // nonce differs
        Bytes tag_flip = link_ct;
        tag_flip.back() ^= 1U;
        LM_CHECK(open_bytes(fresh_rx, link_counter, view(laad), tag_flip, plain, verdict) ==
                 Status::AuthRejected);
        LM_CHECK_OK(open_bytes(fresh_rx, link_counter, view(laad), link_ct, plain, verdict));
    }
}

LM_TEST("S04 replay window: duplicate, out-of-window, reorder, same counter with other payload") {
    LM_CHECK_OK(crypto_init());
    const Bytes seed(32, 0x5A);
    RecordSession a, b;
    Sha256Digest h{};
    make_pair(seed, base_context(), Purpose::Link, a, b, h);
    const Bytes aad = {1, 2, 3, 4};
    std::vector<Bytes> cts(1);
    uint64_t c = 0;
    for (int i = 1; i <= 70; ++i) {
        cts.push_back(seal_bytes(a, view(aad), Bytes(20, static_cast<uint8_t>(i)), c));
        LM_CHECK_EQ(c, static_cast<uint64_t>(i)); // counters start at 1 and never skip
    }
    Bytes pt;
    ReplayVerdict v{};
    // open() alone never consumes the window (docs/06 §6): the caller accepts after its own checks.
    LM_CHECK_OK(open_bytes(b, 1, view(aad), cts[1], pt, v));
    LM_CHECK_OK(open_bytes(b, 1, view(aad), cts[1], pt, v));
    for (uint64_t i = 1; i <= 70; ++i) {
        LM_CHECK_OK(open_bytes(b, i, view(aad), cts[i], pt, v));
        LM_CHECK(v == ReplayVerdict::Fresh);
        LM_CHECK(pt == Bytes(20, static_cast<uint8_t>(i)));
        b.accept(i);
    }
    // Duplicate inside the window: authentic, reported as Replay + Duplicate, never re-applied.
    LM_CHECK(open_bytes(b, 70, view(aad), cts[70], pt, v) == Status::Replay);
    LM_CHECK(v == ReplayVerdict::Duplicate);
    LM_CHECK(open_bytes(b, 7, view(aad), cts[7], pt, v) == Status::Replay); // 70-7 = 63: last slot
    LM_CHECK(v == ReplayVerdict::Duplicate);
    LM_CHECK(open_bytes(b, 6, view(aad), cts[6], pt, v) == Status::Replay); // 64 behind
    LM_CHECK(v == ReplayVerdict::TooOld);
    LM_CHECK(open_bytes(b, 1, view(aad), cts[1], pt, v) == Status::Replay);
    LM_CHECK(v == ReplayVerdict::TooOld);
    // Same counter, different payload: a peer that lost its counters (same key, same nonce).
    RecordSession twin_a, twin_b;
    Sha256Digest h2{};
    make_pair(seed, base_context(), Purpose::Link, twin_a, twin_b, h2);
    Bytes other;
    for (int i = 1; i <= 70; ++i) {
        other = seal_bytes(twin_a, view(aad), Bytes(20, 0xEE), c);
    }
    LM_CHECK_EQ(c, 70u);
    LM_CHECK(open_bytes(b, 70, view(aad), other, pt, v) == Status::Replay); // duplicate, not applied
    LM_CHECK(v == ReplayVerdict::Duplicate);
    Bytes flipped = cts[70];
    flipped[3] ^= 1U;
    LM_CHECK(open_bytes(b, 70, view(aad), flipped, pt, v) == Status::AuthRejected);
    // Reflection: a packet sent by A is not opened by A's own receive key.
    LM_CHECK(open_bytes(a, 1, view(aad), cts[1], pt, v) == Status::AuthRejected);

    // Reorder and gaps inside a fresh window.
    RecordSession rb;
    RecordSession ra;
    make_pair(seed, base_context(), Purpose::End, ra, rb, h);
    std::vector<Bytes> many(1);
    for (int i = 1; i <= 220; ++i) {
        many.push_back(seal_bytes(ra, view(aad), Bytes(4, static_cast<uint8_t>(i)), c));
    }
    for (uint64_t i : {5u, 3u, 200u, 137u}) {
        LM_CHECK_OK(open_bytes(rb, i, view(aad), many[i], pt, v));
        LM_CHECK(v == ReplayVerdict::Fresh);
        rb.accept(i);
    }
    LM_CHECK(open_bytes(rb, 3, view(aad), many[3], pt, v) == Status::Replay);
    LM_CHECK(open_bytes(rb, 136, view(aad), many[136], pt, v) == Status::Replay);
    LM_CHECK(v == ReplayVerdict::TooOld); // 200 - 136 = 64
    LM_CHECK(open_bytes(rb, 0, view(aad), many[1], pt, v) == Status::BadFrame); // counter 0 reserved
    LM_CHECK(open_bytes(rb, 9, view(aad), Bytes(15, 0), pt, v) == Status::BadFrame); // < tag
    LM_CHECK_EQ(rb.window().highest(), 200u);
}

LM_TEST("S04 transmit counters: start at 1, never reused, never wrap, seal order enforced") {
    LM_CHECK_OK(crypto_init());
    RecordSession s;
    uint64_t c = 0;
    LM_CHECK(s.next_counter(c) == Status::RecoveryRequired); // no keys installed
    const Bytes seed(32, 0x33);
    RecordSession peer;
    Sha256Digest h{};
    make_pair(seed, base_context(), Purpose::Usb, s, peer, h);
    const Bytes aad = {9};
    const Bytes pt = {1, 2, 3};
    Bytes out(19);
    LM_CHECK(s.seal(1, view(aad), view(pt), MutByteView{out.data(), out.size()}) ==
             Status::InvalidArgument); // never reserved
    LM_CHECK_OK(s.next_counter(c));
    LM_CHECK_EQ(c, 1u);
    LM_CHECK(s.seal(1, view(aad), view(pt), MutByteView{out.data(), 18}) == Status::BufferTooSmall);
    LM_CHECK_OK(s.seal(1, view(aad), view(pt), MutByteView{out.data(), out.size()}));
    LM_CHECK(s.seal(1, view(aad), view(pt), MutByteView{out.data(), out.size()}) ==
             Status::InvalidArgument); // a nonce is used once; changed content needs a new counter
    LM_CHECK(s.seal(0, view(aad), view(pt), MutByteView{out.data(), out.size()}) ==
             Status::InvalidArgument);
    uint64_t last = 1;
    while (s.next_counter(c) == Status::Ok) {
        last = c;
    }
    LM_CHECK_EQ(last, k_max_records_per_key);
    LM_CHECK(s.next_counter(c) == Status::SessionRefreshRequired); // no wrap
    RecordSession rx;
    RecordSession dummy;
    make_pair(seed, base_context(), Purpose::Usb, dummy, rx, h);
    Bytes plain;
    ReplayVerdict v{};
    LM_CHECK(open_bytes(rx, k_max_records_per_key + 1, view(aad), Bytes(19, 0), plain, v) ==
             Status::SessionRefreshRequired);
    s.wipe();
    LM_CHECK(!s.active());
    LM_CHECK(s.next_counter(c) == Status::RecoveryRequired);
}

LM_TEST("S02 any change of purpose, domain, identity or generation gives other keys; cross-open fails") {
    LM_CHECK_OK(crypto_init());
    const Bytes seed(32, 0x77);
    const SessionContext base = base_context();
    std::vector<SessionContext> variants;
    auto add = [&](auto mutate) {
        SessionContext c = base;
        mutate(c);
        variants.push_back(c);
    };
    add([](SessionContext &c) { c.purpose = Purpose::End; });
    add([](SessionContext &c) { c.purpose = Purpose::Usb; });
    add([](SessionContext &c) { c.fleet.bytes[15] ^= 1U; });
    add([](SessionContext &c) { c.domain.bytes[0] ^= 1U; });
    add([](SessionContext &c) { c.initiator.bytes[31] ^= 1U; });
    add([](SessionContext &c) { c.responder.bytes[0] ^= 1U; });
    add([](SessionContext &c) { c.assignment_i = AssignmentGen{c.assignment_i.value() + 1}; });
    add([](SessionContext &c) { c.assignment_r = AssignmentGen{c.assignment_r.value() + 1}; });
    add([](SessionContext &c) { c.membership_i = MembershipGen{c.membership_i.value() + 1}; });
    add([](SessionContext &c) { c.membership_r = MembershipGen{c.membership_r.value() + 1}; });
    add([](SessionContext &c) { c.credential_hash_i[7] ^= 1U; });
    add([](SessionContext &c) { c.credential_hash_r[7] ^= 1U; });
    add([](SessionContext &c) { std::swap(c.initiator, c.responder); }); // roles are not symmetric

    Sha256Digest base_h{};
    LM_CHECK_OK(context_hash(base, base_h));
    RecordKeys base_keys;
    LM_CHECK_OK(derive_record_keys(view(seed), base_h, base.purpose, true, base_keys));
    RecordSession sender;
    LM_CHECK_OK(sender.install(std::move(base_keys)));
    const Bytes aad = {0};
    uint64_t c = 0;
    const Bytes ct = seal_bytes(sender, view(aad), Bytes(8, 1), c);
    for (const SessionContext &v : variants) {
        Sha256Digest h{};
        LM_CHECK_OK(context_hash(v, h));
        LM_CHECK(h != base_h);
        RecordKeys k;
        LM_CHECK_OK(derive_record_keys(view(seed), h, v.purpose, false, k));
        RecordSession rx;
        LM_CHECK_OK(rx.install(std::move(k)));
        Bytes pt;
        ReplayVerdict verdict{};
        LM_CHECK(open_bytes(rx, 1, view(aad), ct, pt, verdict) == Status::AuthRejected);
    }
    // A generation above u63 is not encodable (docs/06 §4, control.cddl u63).
    SessionContext big = base;
    big.assignment_i = AssignmentGen{k_u63_max + 1};
    Sha256Digest dummy{};
    LM_CHECK(context_hash(big, dummy) == Status::InvalidArgument);
    SessionContext bad_purpose = base;
    bad_purpose.purpose = static_cast<Purpose>(9); // only link, end and USB exist
    LM_CHECK(context_hash(bad_purpose, dummy) == Status::InvalidArgument);
    bad_purpose.purpose = static_cast<Purpose>(0);
    LM_CHECK(context_hash(bad_purpose, dummy) == Status::InvalidArgument);
    // A different seed (other handshake) never yields the same keys either.
    RecordKeys other;
    LM_CHECK_OK(derive_record_keys(view(Bytes(32, 0x78)), base_h, base.purpose, true, other));
    RecordKeys again;
    LM_CHECK_OK(derive_record_keys(view(seed), base_h, base.purpose, true, again));
    LM_CHECK(other.tx.key != again.tx.key && other.tx.prefix != again.tx.prefix);
    LM_CHECK(other.tx.key != other.rx.key); // direction separation
    LM_CHECK(derive_record_keys(view(Bytes(31, 0)), base_h, base.purpose, true, other) ==
             Status::InvalidArgument);
}

// ================================ identity, COSE ==============================================

namespace {

PublicKey golden_public() {
    const Bytes k = hex(gen::golden::cose::cose_key_hex);
    PublicKey p;
    std::memcpy(p.x.data(), k.data() + 8, 32);
    std::memcpy(p.y.data(), k.data() + 43, 32);
    return p;
}

struct Identity {
    KeyHandle key;
    PublicKey pub;
    DeviceId id;
    std::array<uint8_t, k_ccs_max_bytes> ccs{};
    std::size_t ccs_len = 0;
    ByteView ccs_view() const { return ByteView{ccs.data(), ccs_len}; }
    Identity() = default;
    Identity(const Identity &) = delete;
    Identity &operator=(const Identity &) = delete;
    ~Identity() { destroy_key(key); }
};

void make_identity(Identity &out, const char *subject) {
    std::array<uint8_t, 32> scalar{};
    LM_CHECK_OK(generate_signing_key(scalar, out.pub));
    LM_CHECK_OK(import_signing_key(view(scalar), out.key));
    secure_zero(MutByteView{scalar.data(), scalar.size()});
    LM_CHECK_OK(device_id_of(out.pub, out.id));
    LM_CHECK_OK(ccs_encode(ByteView{reinterpret_cast<const uint8_t *>(subject), std::strlen(subject)},
                           out.pub, MutByteView{out.ccs.data(), out.ccs.size()}, out.ccs_len));
}

} // namespace

LM_TEST("S07 invalid points, scalars, lengths and signatures are always rejected") {
    LM_CHECK_OK(crypto_init());
    const PublicKey good = golden_public();
    LM_CHECK_OK(validate_public_key(good));
    const Bytes msg = {1, 2, 3, 4, 5};
    Identity id;
    make_identity(id, "s07");
    Signature sig{};
    LM_CHECK_OK(sign_es256(id.key, view(msg), sig));
    LM_CHECK_OK(verify_es256(id.pub, view(msg), view(sig)));

    std::vector<PublicKey> bad;
    PublicKey p = good;
    p.y[31] ^= 1U; // off the curve
    bad.push_back(p);
    p = good;
    p.x[0] ^= 0x80U;
    bad.push_back(p);
    bad.push_back(PublicKey{});                        // (0, 0)
    p = good;
    p.x.fill(0xFF);                                    // x >= p
    bad.push_back(p);
    p = good;
    p.y.fill(0xFF);                                    // y >= p
    bad.push_back(p);
    p = good;
    p.x = good.y;                                      // swapped coordinates
    p.y = good.x;
    bad.push_back(p);
    for (const PublicKey &k : bad) {
        LM_CHECK(validate_public_key(k) != Status::Ok);
        LM_CHECK(verify_es256(k, view(msg), view(sig)) == Status::InvalidArgument);
        std::array<uint8_t, k_ccs_max_bytes> ccs{};
        std::size_t len = 0;
        LM_CHECK_OK(ccs_encode(ByteView{reinterpret_cast<const uint8_t *>("x"), 1}, k,
                               MutByteView{ccs.data(), ccs.size()}, len));
        PublicKey out;
        DeviceId dev;
        LM_CHECK(ccs_parse(ByteView{ccs.data(), len}, out, dev) != Status::Ok);
    }
    // Private scalars: 0, n, n+1, 2^256-1 and wrong lengths never become keys; n-1 does.
    const Bytes n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    Bytes n_minus_1 = n;
    n_minus_1.back() -= 1;
    Bytes n_plus_1 = n;
    n_plus_1.back() += 1;
    KeyHandle h;
    for (const Bytes &s : {Bytes(32, 0), n, n_plus_1, Bytes(32, 0xFF)}) {
        LM_CHECK(import_signing_key(view(s), h) != Status::Ok);
        LM_CHECK_EQ(h.id, 0u);
    }
    LM_CHECK(import_signing_key(view(Bytes(31, 1)), h) == Status::InvalidArgument);
    LM_CHECK(import_signing_key(view(Bytes(33, 1)), h) == Status::InvalidArgument);
    LM_CHECK_OK(import_signing_key(view(n_minus_1), h));
    destroy_key(h);
    LM_CHECK_EQ(h.id, 0u);

    // Signatures: wrong message (hash), bit flips, zero/short/long, r = 0, s = 0, other key.
    Bytes other_msg = msg;
    other_msg[0] ^= 1U;
    LM_CHECK(verify_es256(id.pub, view(other_msg), view(sig)) == Status::AuthRejected);
    for (std::size_t i : {0u, 31u, 32u, 63u}) {
        Signature s2 = sig;
        s2[i] ^= 0x01U;
        LM_CHECK(verify_es256(id.pub, view(msg), view(s2)) == Status::AuthRejected);
    }
    Signature zero{};
    LM_CHECK(verify_es256(id.pub, view(msg), view(zero)) == Status::AuthRejected);
    Signature r0 = sig;
    std::memset(r0.data(), 0, 32);
    LM_CHECK(verify_es256(id.pub, view(msg), view(r0)) == Status::AuthRejected);
    Signature s0 = sig;
    std::memset(s0.data() + 32, 0, 32);
    LM_CHECK(verify_es256(id.pub, view(msg), view(s0)) == Status::AuthRejected);
    LM_CHECK(verify_es256(id.pub, view(msg), ByteView{sig.data(), 63}) == Status::AuthRejected);
    Bytes long_sig(sig.begin(), sig.end());
    long_sig.push_back(0);
    LM_CHECK(verify_es256(id.pub, view(msg), view(long_sig)) == Status::AuthRejected);
    LM_CHECK(verify_es256(good, view(msg), view(sig)) == Status::AuthRejected); // another key
    KeyHandle none;
    LM_CHECK(sign_es256(none, view(msg), sig) == Status::InvalidArgument);
}

LM_TEST("S07 CCS: one canonical encoding, DeviceId derived from the key, strict parse") {
    LM_CHECK_OK(crypto_init());
    Identity id;
    make_identity(id, "unit-01");
    PublicKey key;
    DeviceId dev;
    LM_CHECK_OK(ccs_parse(id.ccs_view(), key, dev));
    LM_CHECK(dev == id.id && key.x == id.pub.x && key.y == id.pub.y);
    // DeviceId = SHA-256(golden COSE_Key) for the golden key, and the encoding is byte-exact.
    const PublicKey g = golden_public();
    std::array<uint8_t, k_cose_key_bytes> ck{};
    LM_CHECK_OK(cose_key_encode(g, MutByteView{ck.data(), ck.size()}));
    LM_CHECK(Bytes(ck.begin(), ck.end()) == hex(gen::golden::cose::cose_key_hex));
    DeviceId gid;
    LM_CHECK_OK(device_id_of(g, gid));
    LM_CHECK(Bytes(gid.bytes.begin(), gid.bytes.end()) == hex(gen::golden::cose::device_id_hex));
    LM_CHECK(cose_key_encode(g, MutByteView{ck.data(), 74}) == Status::BufferTooSmall);

    Bytes ccs(id.ccs.begin(), id.ccs.begin() + static_cast<long>(id.ccs_len));
    auto rejects = [&](const Bytes &b) {
        PublicKey k;
        DeviceId d;
        return ccs_parse(view(b), k, d) != Status::Ok;
    };
    Bytes trailing = ccs;
    trailing.push_back(0);
    LM_CHECK(rejects(trailing));
    LM_CHECK(rejects(Bytes(ccs.begin(), ccs.end() - 1)));
    Bytes extra_key = ccs;
    extra_key[0] = 0xA3; // three entries announced
    LM_CHECK(rejects(extra_key));
    Bytes swapped_keys = ccs; // {8: ..., 2: ...}: not the deterministic order
    swapped_keys[1] = 0x08;
    LM_CHECK(rejects(swapped_keys));
    Bytes long_head = {0xA2, 0x02, 0x78, 0x07}; // text length 7 in the two-byte form: not shortest
    long_head.insert(long_head.end(), ccs.begin() + 2 + 1, ccs.end());
    LM_CHECK(rejects(long_head));
    Bytes ctrl = ccs;
    ctrl[3] = 0x0A; // control character in the subject
    LM_CHECK(rejects(ctrl));
    std::array<uint8_t, k_ccs_max_bytes> tmp{};
    std::size_t len = 0;
    LM_CHECK(ccs_encode(view(Bytes(65, 'a')), id.pub, MutByteView{tmp.data(), tmp.size()}, len) ==
             Status::InvalidArgument);
    LM_CHECK_OK(ccs_encode(view(Bytes(64, 'a')), id.pub, MutByteView{tmp.data(), tmp.size()}, len));
    LM_CHECK(len <= k_ccs_max_bytes);
    // One public key, one DeviceId: another key differs.
    Identity other;
    make_identity(other, "unit-01");
    LM_CHECK(other.id != id.id);
}

LM_TEST("COSE_Sign1: golden object verifies; own objects round-trip; malformed ones are rejected") {
    LM_CHECK_OK(crypto_init());
    namespace c = gen::golden::cose;
    const PublicKey g = golden_public();
    const Bytes golden = hex(c::cose_sign1_hex);
    Sign1View v;
    LM_CHECK_OK(sign1_verify(g, view(golden), v));
    LM_CHECK(Bytes(v.kid.bytes.begin(), v.kid.bytes.end()) == hex(c::device_id_hex));
    LM_CHECK(Bytes(v.payload.begin(), v.payload.end()) == hex(c::payload_hex));
    LM_CHECK(Bytes(v.signature.begin(), v.signature.end()) == hex(c::signature_raw_hex));
    // The golden signature is ES256 over the golden Sig_structure bytes.
    const Bytes tbs = hex(c::sig_structure_hex);
    LM_CHECK_OK(verify_es256(g, view(tbs), v.signature));
    // Any single-bit change anywhere is rejected (structure or signature).
    for (std::size_t i = 0; i < golden.size(); ++i) {
        Bytes m = golden;
        m[i] ^= 0x01U;
        Sign1View out;
        LM_CHECK(sign1_verify(g, view(m), out) != Status::Ok);
    }
    // Truncation and trailing bytes.
    Sign1View out;
    LM_CHECK(sign1_verify(g, ByteView{golden.data(), golden.size() - 1}, out) == Status::BadFrame);
    Bytes longer = golden;
    longer.push_back(0);
    LM_CHECK(sign1_verify(g, view(longer), out) == Status::BadFrame);

    Identity a, b;
    make_identity(a, "issuer");
    make_identity(b, "other");
    std::vector<Bytes> objects;
    for (std::size_t n : {0u, 1u, 23u, 24u, 255u, 256u, 1000u, 3900u}) {
        const Bytes payload(n, static_cast<uint8_t>(n));
        Bytes msg(n + 128);
        std::size_t len = 0;
        LM_CHECK_OK(sign1_create(a.key, a.id, view(payload), MutByteView{msg.data(), msg.size()}, len));
        msg.resize(len);
        LM_CHECK_OK(sign1_verify(a.pub, view(msg), out));
        LM_CHECK(bytes_equal(out.payload, view(payload)));
        LM_CHECK(sign1_verify(b.pub, view(msg), out) == Status::AuthRejected); // kid != key
        objects.push_back(msg);
    }
    // A kid can not be paired with another key: a signature by b claiming a's kid does not verify.
    Bytes forged(200);
    std::size_t flen = 0;
    LM_CHECK(sign1_create(b.key, a.id, view(Bytes(4, 1)), MutByteView{forged.data(), forged.size()}, flen) ==
             Status::InvalidArgument); // FIX1-23: the signer cannot claim another identity
    LM_CHECK(sign1_create(a.key, b.id, view(Bytes(4, 1)), MutByteView{forged.data(), forged.size()}, flen) ==
             Status::InvalidArgument);
    // Non-shortest payload head (58 03 instead of 43) is a structure error, not a valid alias.
    Bytes small(128);
    std::size_t slen = 0;
    LM_CHECK_OK(sign1_create(a.key, a.id, view(Bytes(3, 7)), MutByteView{small.data(), small.size()}, slen));
    small.resize(slen);
    Bytes aliased(small.begin(), small.begin() + 42 + 1);
    aliased.push_back(0x58);
    aliased.push_back(0x03);
    aliased.insert(aliased.end(), small.begin() + 43 + 1, small.end());
    LM_CHECK(sign1_parse(view(aliased), out) == Status::BadFrame);
    // Oversize payloads are refused before signing.
    Bytes big(5000);
    std::size_t blen = 0;
    LM_CHECK(sign1_create(a.key, a.id, view(Bytes(4090, 1)), MutByteView{big.data(), big.size()}, blen) ==
             Status::PayloadTooLarge);
}

// ================================ EDHOC ========================================================

LM_TEST("S01 RFC 9529 chapter 3 trace (method 3, suite 2) replays through the LeanMesh glue") {
    char why[200] = "";
    const int rc = lm_test_rfc9529_chapter3(why, sizeof why);
    if (rc != 0) {
        lmtest::fail(__FILE__, __LINE__, why);
    }
    LM_CHECK_EQ(rc, 0);
}

namespace {

// Stand-in for the slow-job worker: executes the armed job body synchronously and completes it
// through a real JobTable (ticket match, one public-key job at a time), as the owner would.
struct Worker {
    sim::SimStore store{sim::StoreGeometry{}};
    JobTable<4> table;

    Status run(HandshakeSlot &slot, HsStep step, ByteView in = ByteView{}) {
        Status st = slot.prepare(step, in);
        if (st != Status::Ok) {
            return st;
        }
        JobTicket t;
        LM_CHECK_OK(table.reserve(JobOwner::Test, Handle{1, 1}, JobClass::PublicKey, t));
        port::JobEnv env{store};
        const Status job = HandshakeSlot::run_job(env, &slot);
        JobOrigin origin;
        LM_CHECK(table.complete(port::JobCompletion{t.table_index, t.job_id, job}, origin));
        return slot.complete(job);
    }
};

SessionContext pair_context(const Identity &i, const Identity &r) {
    SessionContext c = base_context();
    c.initiator = i.id;
    c.responder = r.id;
    c.purpose = Purpose::Link;
    return c;
}

struct Mutation {
    int message = 0; // 0 none, else 1..4
    enum class Kind { Flip, Truncate, Extend } kind = Kind::Flip;
    std::size_t pos = 0;
    // Static G_X substitute for m1 (S07 invalid ephemeral), applied after `kind` when non-empty.
    Bytes replace_m1;
    Bytes m1_suffix; // appended to m1 (EAD tests)
};

struct RunResult {
    bool completed = false;
    int failed_step = 0; // 1..4 message number, 5 export
    Status status = Status::Ok;
    RecordKeys init_keys;
    RecordKeys resp_keys;
    std::size_t sizes[5] = {0, 0, 0, 0, 0};
    Bytes msgs[5];
};

Bytes apply(const Bytes &m, const Mutation &mu, int index) {
    if (mu.message != index) {
        return m;
    }
    Bytes out = m;
    switch (mu.kind) {
    case Mutation::Kind::Flip: out[mu.pos % out.size()] ^= static_cast<uint8_t>(1U << (mu.pos % 8)); break;
    case Mutation::Kind::Truncate: out.pop_back(); break;
    case Mutation::Kind::Extend: out.push_back(0x00); break;
    }
    return out;
}

// Full initiator/responder exchange through the job bodies. On any failed step both slots are
// cancelled and the status is returned in RunResult.
RunResult run_handshake(Worker &w, HandshakeSlot &I, HandshakeSlot &R, const Identity &ia,
                        const Identity &rb, const SessionContext &ctx_i, const SessionContext &ctx_r,
                        const Mutation &mu, const ByteView *initiator_peers = nullptr,
                        const ByteView *responder_peers = nullptr) {
    RunResult res;
    const ByteView rb_ccs = rb.ccs_view();
    const ByteView ia_ccs = ia.ccs_view();
    LM_CHECK_OK(I.begin(HsRole::Initiator, ia.key, ia_ccs, initiator_peers ? initiator_peers : &rb_ccs, 1));
    LM_CHECK_OK(R.begin(HsRole::Responder, rb.key, rb_ccs, responder_peers ? responder_peers : &ia_ccs, 1));
    auto fail = [&](int step, Status st) -> RunResult {
        res.failed_step = step;
        res.status = st;
        (void)I.cancel();
        (void)R.cancel();
        LM_CHECK(I.idle() && R.idle());
        return std::move(res);
    };
    auto bytes_of = [](ByteView v) { return Bytes(v.begin(), v.end()); };

    Status st = w.run(I, HsStep::M1Compose);
    if (st != Status::Ok) return fail(1, st);
    res.msgs[1] = bytes_of(I.output());
    Bytes m = apply(res.msgs[1], mu, 1);
    if (!mu.replace_m1.empty()) {
        m = mu.replace_m1;
    }
    m.insert(m.end(), mu.m1_suffix.begin(), mu.m1_suffix.end());
    st = w.run(R, HsStep::M1Process, view(m));
    if (st != Status::Ok) return fail(1, st);
    st = w.run(R, HsStep::M2Compose);
    if (st != Status::Ok) return fail(2, st);
    res.msgs[2] = bytes_of(R.output());
    m = apply(res.msgs[2], mu, 2);
    st = w.run(I, HsStep::M2Process, view(m));
    if (st != Status::Ok) return fail(2, st);
    st = w.run(I, HsStep::M3Compose);
    if (st != Status::Ok) return fail(3, st);
    res.msgs[3] = bytes_of(I.output());
    m = apply(res.msgs[3], mu, 3);
    st = w.run(R, HsStep::M3Process, view(m));
    if (st != Status::Ok) return fail(3, st);
    st = w.run(R, HsStep::M4Compose);
    if (st != Status::Ok) return fail(4, st);
    res.msgs[4] = bytes_of(R.output());
    m = apply(res.msgs[4], mu, 4);
    st = w.run(I, HsStep::M4Process, view(m));
    if (st != Status::Ok) return fail(4, st);

    st = I.set_context(ctx_i);
    if (st == Status::Ok) st = R.set_context(ctx_r);
    if (st != Status::Ok) return fail(5, st);
    st = w.run(I, HsStep::Export);
    if (st == Status::Ok) st = w.run(R, HsStep::Export);
    if (st != Status::Ok) return fail(5, st);
    LM_CHECK_OK(I.take_keys(res.init_keys));
    LM_CHECK_OK(R.take_keys(res.resp_keys));
    res.completed = true;
    return res;
}

bool contains(const void *hay, std::size_t hay_len, const uint8_t *needle, std::size_t n) {
    const auto *h = static_cast<const uint8_t *>(hay);
    for (std::size_t i = 0; i + n <= hay_len; ++i) {
        if (std::memcmp(h + i, needle, n) == 0) {
            return true;
        }
    }
    return false;
}

} // namespace

LM_TEST("crypto_link_check self test (keys, COSE, handshake, records) passes natively") {
    LM_CHECK_EQ(lm_security_link_check(), 0);
}

LM_TEST("S01 method-0/suite-3 loopback through the job bodies: keys mirror and carry records") {
    LM_CHECK_OK(crypto_init());
    Identity a, b;
    make_identity(a, "node-a");
    make_identity(b, "node-b");
    Worker w;
    HandshakeSlot I, R;
    const SessionContext ctx = pair_context(a, b);
    RunResult r = run_handshake(w, I, R, a, b, ctx, ctx, Mutation{});
    LM_CHECK(r.completed);
    LM_CHECK(r.msgs[1].size() < 64 && r.msgs[2].size() < 160 && r.msgs[3].size() < 160 &&
             r.msgs[4].size() < 32); // every message fits the bootstrap carrier budget
    // The responder's tx key is the initiator's rx key and vice versa (direction 0 = I -> R).
    LM_CHECK(r.init_keys.tx.key == r.resp_keys.rx.key && r.init_keys.tx.prefix == r.resp_keys.rx.prefix);
    LM_CHECK(r.init_keys.rx.key == r.resp_keys.tx.key && r.init_keys.rx.prefix == r.resp_keys.tx.prefix);
    LM_CHECK(r.init_keys.tx.key != r.init_keys.rx.key);
    const auto first_tx = r.init_keys.tx.key; // install() zeroes the moved-from keys
    const auto first_rx = r.init_keys.rx.key;
    RecordSession si, sr;
    LM_CHECK_OK(si.install(std::move(r.init_keys)));
    LM_CHECK_OK(sr.install(std::move(r.resp_keys)));
    Sha256Digest h{};
    LM_CHECK_OK(context_hash(ctx, h));
    const Bytes aad(h.begin(), h.end());
    uint64_t c = 0;
    const Bytes ct = seal_bytes(si, view(aad), Bytes{'h', 'i'}, c);
    Bytes pt;
    ReplayVerdict v{};
    LM_CHECK_OK(open_bytes(sr, c, view(aad), ct, pt, v));
    LM_CHECK(pt == (Bytes{'h', 'i'}));
    const Bytes back = seal_bytes(sr, view(aad), Bytes{'y', 'o'}, c);
    LM_CHECK_OK(open_bytes(si, c, view(aad), back, pt, v));
    LM_CHECK(pt == (Bytes{'y', 'o'}));

    // A second handshake between the same pair (fresh ephemerals) never repeats keys.
    const RunResult r2 = run_handshake(w, I, R, a, b, ctx, ctx, Mutation{});
    LM_CHECK(r2.completed);
    LM_CHECK(r2.init_keys.tx.key != first_tx && r2.init_keys.rx.key != first_rx);
    LM_CHECK(r2.msgs[1] != r.msgs[1]);
}

LM_TEST("S02 handshake with a different context on each side derives keys that cannot talk") {
    LM_CHECK_OK(crypto_init());
    Identity a, b;
    make_identity(a, "node-a");
    make_identity(b, "node-b");
    Worker w;
    HandshakeSlot I, R;
    SessionContext ci = pair_context(a, b);
    SessionContext cr = ci;
    cr.domain.bytes[3] ^= 1U;
    RunResult r = run_handshake(w, I, R, a, b, ci, cr, Mutation{});
    LM_CHECK(r.completed); // EDHOC itself succeeds; the LM context is what separates the keys
    LM_CHECK(r.init_keys.tx.key != r.resp_keys.rx.key);
    RecordSession si, sr;
    LM_CHECK_OK(si.install(std::move(r.init_keys)));
    LM_CHECK_OK(sr.install(std::move(r.resp_keys)));
    const Bytes aad = {0};
    uint64_t c = 0;
    const Bytes ct = seal_bytes(si, view(aad), Bytes(5, 1), c);
    Bytes pt;
    ReplayVerdict v{};
    LM_CHECK(open_bytes(sr, c, view(aad), ct, pt, v) == Status::AuthRejected);

    // set_context refuses identities that are not the authenticated ones (or swapped roles).
    const RunResult r2 = [&] {
        SessionContext wrong = ci;
        wrong.responder.bytes[0] ^= 1U;
        return run_handshake(w, I, R, a, b, wrong, ci, Mutation{});
    }();
    LM_CHECK(!r2.completed && r2.failed_step == 5 && r2.status == Status::AuthRejected);
    const RunResult r3 = [&] {
        SessionContext swapped = ci;
        std::swap(swapped.initiator, swapped.responder);
        return run_handshake(w, I, R, a, b, ci, swapped, Mutation{});
    }();
    LM_CHECK(!r3.completed && r3.failed_step == 5 && r3.status == Status::AuthRejected);
}

LM_TEST("S07 handshake refuses unknown peers, invalid ephemerals, critical EAD, self and bad CCS") {
    LM_CHECK_OK(crypto_init());
    Identity a, b, mallory;
    make_identity(a, "node-a");
    make_identity(b, "node-b");
    make_identity(mallory, "mallory");
    Worker w;
    HandshakeSlot I, R;
    const SessionContext ctx = pair_context(a, b);

    // The responder only trusts mallory: node-a's message 3 names an unknown kid.
    const ByteView only_mallory = mallory.ccs_view();
    RunResult r = run_handshake(w, I, R, a, b, ctx, ctx, Mutation{}, nullptr, &only_mallory);
    LM_CHECK(!r.completed && r.failed_step == 3 && r.status == Status::AuthRejected);
    // The initiator expects mallory but b answers: message 2 fails.
    r = run_handshake(w, I, R, a, b, ctx, ctx, Mutation{}, &only_mallory, nullptr);
    LM_CHECK(!r.completed && r.failed_step == 2 && r.status == Status::AuthRejected);

    // Invalid ephemeral in message 1: a coordinate with no curve point (x = 1) and x >= p.
    RunResult probe = run_handshake(w, I, R, a, b, ctx, ctx, Mutation{});
    LM_CHECK(probe.completed);
    for (int variant = 0; variant < 2; ++variant) {
        Mutation mu;
        mu.replace_m1 = probe.msgs[1];
        // m1 = 03 | suites | 58 20 <G_X:32> | C_I : G_X starts after the 2-byte head.
        std::size_t gx = 0;
        for (std::size_t i = 0; i + 1 < mu.replace_m1.size(); ++i) {
            if (mu.replace_m1[i] == 0x58 && mu.replace_m1[i + 1] == 0x20) {
                gx = i + 2;
                break;
            }
        }
        LM_CHECK(gx != 0);
        std::memset(mu.replace_m1.data() + gx, variant == 0 ? 0x00 : 0xFF, 32);
        if (variant == 0) {
            mu.replace_m1[gx + 31] = 0x01; // x = 1: x^3 - 3x + b is a non-residue mod p
        }
        r = run_handshake(w, I, R, a, b, ctx, ctx, mu);
        LM_CHECK(!r.completed && (r.failed_step == 1 || r.failed_step == 2)); // no secret is derived
    }

    // EAD: a critical (negative label) item is fatal, padding (label 0) and unknown non-critical
    // items are ignored (docs/06 §9). The extra bytes are part of message 1's transcript, so the
    // handshake as a whole still fails later for the initiator; what matters is where.
    Mutation crit;
    crit.m1_suffix = {0x20}; // EAD_1 = label -1
    r = run_handshake(w, I, R, a, b, ctx, ctx, crit);
    LM_CHECK(!r.completed && r.failed_step == 1 && r.status == Status::AuthRejected);
    Mutation pad;
    pad.m1_suffix = {0x00}; // EAD_1 = label 0 (padding), accepted by the responder
    r = run_handshake(w, I, R, a, b, ctx, ctx, pad);
    LM_CHECK(!r.completed && r.failed_step == 2); // past m1, then transcript mismatch at m2
    Mutation non_critical;
    non_critical.m1_suffix = {0x0A};
    r = run_handshake(w, I, R, a, b, ctx, ctx, non_critical);
    LM_CHECK(!r.completed && r.failed_step == 2);

    // Local problems: a CCS that is not the signing key's, a candidate equal to ourselves, and
    // garbage CCS are rejected by the first job with the slot left idle.
    HandshakeSlot S;
    const ByteView peers[1] = {b.ccs_view()};
    LM_CHECK_OK(S.begin(HsRole::Initiator, mallory.key, a.ccs_view(), peers, 1)); // key != CCS key
    LM_CHECK(w.run(S, HsStep::M1Compose) == Status::InvalidArgument);
    LM_CHECK(S.idle());
    const ByteView self[1] = {a.ccs_view()};
    LM_CHECK_OK(S.begin(HsRole::Initiator, a.key, a.ccs_view(), self, 1));
    LM_CHECK(w.run(S, HsStep::M1Compose) == Status::InvalidArgument);
    Bytes garbage(b.ccs.begin(), b.ccs.begin() + static_cast<long>(b.ccs_len));
    garbage[20] ^= 1U;
    const ByteView bad_peer[1] = {view(garbage)};
    LM_CHECK_OK(S.begin(HsRole::Initiator, a.key, a.ccs_view(), bad_peer, 1));
    LM_CHECK(w.run(S, HsStep::M1Compose) != Status::Ok);
    LM_CHECK(S.idle());
    LM_CHECK(S.begin(HsRole::Initiator, a.key, a.ccs_view(), peers, 0) == Status::InvalidArgument);
    LM_CHECK(S.begin(HsRole::Initiator, KeyHandle{}, a.ccs_view(), peers, 1) == Status::InvalidArgument);
}

LM_TEST("S07 handshake: no single-byte flip, truncation or extension of m1..m4 completes") {
    LM_CHECK_OK(crypto_init());
    Identity a, b;
    make_identity(a, "node-a");
    make_identity(b, "node-b");
    Worker w;
    HandshakeSlot I, R;
    const SessionContext ctx = pair_context(a, b);
    const RunResult ref = run_handshake(w, I, R, a, b, ctx, ctx, Mutation{});
    LM_CHECK(ref.completed);
    // Every byte of every message, one bit changed (the bit varies with the position).
    int runs = 0;
    for (int msg = 1; msg <= 4; ++msg) {
        const std::size_t len = ref.msgs[msg].size();
        for (std::size_t pos = 0; pos < len; ++pos) {
            Mutation mu;
            mu.message = msg;
            mu.kind = Mutation::Kind::Flip;
            mu.pos = pos;
            const RunResult r = run_handshake(w, I, R, a, b, ctx, ctx, mu);
            ++runs;
            if (r.completed) {
                lmtest::fail(__FILE__, __LINE__,
                             "mutated message " + std::to_string(msg) + " byte " +
                                 std::to_string(pos) + " completed the handshake");
            }
        }
        for (auto kind : {Mutation::Kind::Truncate, Mutation::Kind::Extend}) {
            Mutation mu;
            mu.message = msg;
            mu.kind = kind;
            const RunResult r = run_handshake(w, I, R, a, b, ctx, ctx, mu);
            ++runs;
            LM_CHECK(!r.completed);
            LM_CHECK(r.failed_step == msg || (msg == 1 && r.failed_step == 2));
        }
    }
    std::printf("  [info] %d mutated handshakes, none completed\n", runs);
    // Single-message replay: message 3 of another handshake is not accepted by this responder.
    HandshakeSlot I2, R2;
    const RunResult other = run_handshake(w, I2, R2, a, b, ctx, ctx, Mutation{});
    LM_CHECK(other.completed);
    LM_CHECK_OK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), std::array<ByteView, 1>{b.ccs_view()}.data(), 1));
    LM_CHECK_OK(R.begin(HsRole::Responder, b.key, b.ccs_view(), std::array<ByteView, 1>{a.ccs_view()}.data(), 1));
    LM_CHECK_OK(w.run(I, HsStep::M1Compose));
    LM_CHECK_OK(w.run(R, HsStep::M1Process, I.output()));
    LM_CHECK_OK(w.run(R, HsStep::M2Compose));
    LM_CHECK(w.run(R, HsStep::M3Process, view(other.msgs[3])) == Status::AuthRejected);
    (void)I.cancel();
    LM_CHECK(R.idle());
}

LM_TEST("handshake slot: order, zeroisation, cancel while a job is in flight, PSA handles released") {
    LM_CHECK_OK(crypto_init());
    Identity a, b;
    make_identity(a, "node-a");
    make_identity(b, "node-b");
    Worker w;
    HandshakeSlot I, R;
    const SessionContext ctx = pair_context(a, b);

    // Warm up PSA allocations, then require that whole handshakes (also failing ones) release
    // every key slot: heap use returns exactly to the baseline.
    LM_CHECK(run_handshake(w, I, R, a, b, ctx, ctx, Mutation{}).completed);
    const std::size_t baseline = g_live;
    LM_CHECK(run_handshake(w, I, R, a, b, ctx, ctx, Mutation{}).completed);
    Mutation flip;
    flip.message = 3;
    flip.pos = 40;
    LM_CHECK(!run_handshake(w, I, R, a, b, ctx, ctx, flip).completed);
    flip.message = 2;
    LM_CHECK(!run_handshake(w, I, R, a, b, ctx, ctx, flip).completed);
    LM_CHECK_HEAP_EQ(g_live, baseline);

    // Order is enforced by the owner before any job is queued.
    const ByteView peer_b[1] = {b.ccs_view()};
    LM_CHECK_OK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1));
    LM_CHECK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1) == Status::Busy);
    LM_CHECK(I.prepare(HsStep::M3Compose) == Status::Conflict);
    LM_CHECK(I.prepare(HsStep::M1Process, view(Bytes(10, 1))) == Status::Conflict);
    LM_CHECK(I.prepare(HsStep::Export) == Status::Conflict);
    LM_CHECK(I.set_context(ctx) == Status::Conflict); // peer not authenticated yet
    LM_CHECK(I.prepare(HsStep::M1Compose, view(Bytes(1, 1))) == Status::InvalidArgument);
    // Cancel with a job in flight: Busy (memory stays reserved), then the completion discards.
    LM_CHECK_OK(I.prepare(HsStep::M1Compose));
    LM_CHECK(I.in_flight());
    LM_CHECK(I.prepare(HsStep::M1Compose) == Status::Busy);
    LM_CHECK(I.cancel() == Status::Busy);
    port::JobEnv env{w.store};
    const Status job = HandshakeSlot::run_job(env, &I); // the zombie job still runs to completion
    LM_CHECK_OK(job);
    LM_CHECK(I.complete(job) == Status::Conflict);
    LM_CHECK(I.idle() && !I.in_flight());
    // unprepare undoes an arm whose submit failed.
    LM_CHECK_OK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1));
    LM_CHECK_OK(I.prepare(HsStep::M1Compose));
    I.unprepare();
    LM_CHECK(!I.in_flight());
    LM_CHECK_OK(w.run(I, HsStep::M1Compose));
    LM_CHECK(I.cancel() == Status::Ok);
    LM_CHECK_HEAP_EQ(g_live, baseline);

    // Oversize / empty process input.
    const ByteView peer_a[1] = {a.ccs_view()};
    LM_CHECK_OK(R.begin(HsRole::Responder, b.key, b.ccs_view(), peer_a, 1));
    LM_CHECK(R.prepare(HsStep::M1Process, ByteView{}) == Status::InvalidArgument);
    LM_CHECK(R.prepare(HsStep::M1Process, view(Bytes(300, 1))) == Status::PayloadTooLarge);
    LM_CHECK(w.run(R, HsStep::M1Process, view(Bytes(40, 0xAA))) != Status::Ok); // garbage m1
    LM_CHECK(R.idle());

    // Zeroisation: after take_keys() the key bytes are nowhere in the slot object, and a second
    // take fails. The taken keys are the only copy.
    HandshakeSlot *slot = new HandshakeSlot();
    HandshakeSlot &S = *slot;
    LM_CHECK_OK(S.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1));
    HandshakeSlot R3;
    LM_CHECK_OK(R3.begin(HsRole::Responder, b.key, b.ccs_view(), peer_a, 1));
    LM_CHECK_OK(w.run(S, HsStep::M1Compose));
    LM_CHECK_OK(w.run(R3, HsStep::M1Process, S.output()));
    LM_CHECK_OK(w.run(R3, HsStep::M2Compose));
    LM_CHECK_OK(w.run(S, HsStep::M2Process, R3.output()));
    LM_CHECK_OK(w.run(S, HsStep::M3Compose));
    LM_CHECK_OK(w.run(R3, HsStep::M3Process, S.output()));
    LM_CHECK_OK(w.run(R3, HsStep::M4Compose));
    LM_CHECK_OK(w.run(S, HsStep::M4Process, R3.output()));
    LM_CHECK(S.peer_known() && S.peer_device() == b.id && S.local_device() == a.id);
    LM_CHECK_OK(S.set_context(ctx));
    LM_CHECK_OK(R3.set_context(ctx));
    LM_CHECK(S.set_context(ctx) == Status::Ok); // idempotent until the export ran
    RecordKeys none;
    LM_CHECK(S.take_keys(none) == Status::Conflict); // not exported yet
    LM_CHECK_OK(w.run(S, HsStep::Export));
    LM_CHECK_OK(w.run(R3, HsStep::Export));
    LM_CHECK(S.prepare(HsStep::Export) == Status::Conflict);
    RecordKeys taken;
    LM_CHECK_OK(S.take_keys(taken));
    LM_CHECK(!contains(slot, sizeof *slot, taken.tx.key.data(), 16));
    LM_CHECK(!contains(slot, sizeof *slot, taken.rx.key.data(), 16));
    LM_CHECK(S.take_keys(none) == Status::Conflict);
    LM_CHECK(S.idle());
    delete slot;
    RecordKeys peer_keys;
    LM_CHECK_OK(R3.take_keys(peer_keys));
    LM_CHECK(peer_keys.rx.key == taken.tx.key);
    LM_CHECK_HEAP_EQ(g_live, baseline);
}

// ================================ FIX1 regressions ==============================================

static_assert(!std::is_copy_constructible_v<RecordSession> && !std::is_copy_assignable_v<RecordSession>,
              "FIX1-1: a copied session would fork the TX counter (AES-GCM nonce reuse)");
static_assert(!std::is_copy_constructible_v<RecordKeys> && !std::is_copy_assignable_v<RecordKeys>,
              "FIX1-19: key sets are move-only");
static_assert(std::is_nothrow_move_constructible_v<RecordSession> && std::is_nothrow_move_assignable_v<RecordSession>,
              "sessions move between neighbour slots");

LM_TEST("FIX1-2 install refuses an active session: counters and replay window survive, wipe re-arms") {
    LM_CHECK_OK(crypto_init());
    const Bytes seed(32, 0x41);
    RecordSession a, b;
    Sha256Digest h{};
    make_pair(seed, base_context(), Purpose::Link, a, b, h);
    const Bytes aad = {7};
    uint64_t c = 0;
    const Bytes ct1 = seal_bytes(a, view(aad), Bytes(4, 1), c);
    Bytes pt;
    ReplayVerdict v{};
    LM_CHECK_OK(open_bytes(b, c, view(aad), ct1, pt, v));
    b.accept(c);
    // Same keys again into the live sessions: refused, nothing is reset.
    RecordKeys again;
    LM_CHECK_OK(derive_record_keys(view(seed), h, Purpose::Link, true, again));
    LM_CHECK(a.install(std::move(again)) == Status::Conflict);
    LM_CHECK_EQ(a.tx_used(), 1u);
    LM_CHECK_OK(a.next_counter(c));
    LM_CHECK_EQ(c, 2u); // the counter continued: counter 1 is never sealed twice under this key
    RecordKeys rx_again;
    LM_CHECK_OK(derive_record_keys(view(seed), h, Purpose::Link, false, rx_again));
    LM_CHECK(b.install(std::move(rx_again)) == Status::Conflict);
    LM_CHECK(b.window().highest() == 1u);
    LM_CHECK(open_bytes(b, 1, view(aad), ct1, pt, v) == Status::Replay); // still a duplicate
    LM_CHECK(v == ReplayVerdict::Duplicate);
    // After wipe() the object may take keys of a NEW context.
    a.wipe();
    RecordKeys fresh;
    LM_CHECK_OK(derive_record_keys(view(Bytes(32, 0x42)), h, Purpose::Link, true, fresh));
    LM_CHECK_OK(a.install(std::move(fresh)));
    LM_CHECK_EQ(a.tx_used(), 0u);
}

LM_TEST("FIX1-1/19 moving a session transfers counter and window; the source is wiped; keys zeroise") {
    LM_CHECK_OK(crypto_init());
    const Bytes seed(32, 0x43);
    RecordSession a, b;
    Sha256Digest h{};
    make_pair(seed, base_context(), Purpose::Link, a, b, h);
    uint64_t c = 0;
    const Bytes aad = {1};
    (void)seal_bytes(a, view(aad), Bytes(3, 1), c);
    RecordSession moved(std::move(a));
    LM_CHECK(!a.active() && moved.active());
    LM_CHECK_OK(moved.next_counter(c));
    LM_CHECK_EQ(c, 2u); // continues where the source stopped
    LM_CHECK(a.next_counter(c) == Status::RecoveryRequired);
    RecordSession assigned;
    assigned = std::move(moved);
    LM_CHECK(!moved.active() && assigned.tx_used() == 2u);

    // The key container itself: a moved-from set is zero, and the destructor zeroises.
    RecordKeys src;
    LM_CHECK_OK(derive_record_keys(view(seed), h, Purpose::Link, true, src));
    RecordKeys dst(std::move(src));
    const std::array<uint8_t, 16> zero{};
    LM_CHECK(src.tx.key == zero && src.rx.key == zero);
    LM_CHECK(dst.tx.key != zero);
    alignas(RecordKeys) uint8_t storage[sizeof(RecordKeys)];
    auto *k = new (storage) RecordKeys();
    LM_CHECK_OK(derive_record_keys(view(seed), h, Purpose::Link, true, *k));
    LM_CHECK(k->tx.key != zero);
    k->~RecordKeys();
    bool all_zero = true;
    for (uint8_t byte : storage) {
        all_zero = all_zero && byte == 0;
    }
    LM_CHECK(all_zero); // the destructor wiped the key material
}

LM_TEST("FIX1-21 a key that cannot be destroyed fails seal/open instead of reporting success") {
    LM_CHECK_OK(crypto_init());
    const Bytes seed(32, 0x44);
    RecordSession a, b;
    Sha256Digest h{};
    make_pair(seed, base_context(), Purpose::Link, a, b, h);
    const Bytes aad = {2};
    uint64_t c = 0;
    LM_CHECK_OK(a.next_counter(c));
    Bytes out(4 + 16, 0xEE);
    g_destroy_failures = 2; // the one-shot key refuses to go, also on the retry
    LM_CHECK(a.seal(c, view(aad), view(Bytes(4, 9)), MutByteView{out.data(), out.size()}) ==
             Status::RecoveryRequired);
    LM_CHECK(out == Bytes(out.size(), 0)); // no ciphertext leaves a session with a live key
    release_stuck();
    const Bytes good = seal_bytes(a, view(aad), Bytes(4, 9), c);
    Bytes pt(4, 0xEE);
    std::size_t len = 0;
    ReplayVerdict v{};
    g_destroy_failures = 2;
    LM_CHECK(b.open(c, view(aad), view(good), MutByteView{pt.data(), pt.size()}, len, v) ==
             Status::RecoveryRequired);
    LM_CHECK(pt == Bytes(4, 0));
    release_stuck();
    LM_CHECK_OK(open_bytes(b, c, view(aad), good, pt, v)); // healthy again
}

LM_TEST("FIX1-20 handshake teardown that cannot free a PSA key keeps the handle and retries") {
    LM_CHECK_OK(crypto_init());
    Identity a, b;
    make_identity(a, "node-a");
    make_identity(b, "node-b");
    Worker w;
    HandshakeSlot I, R;
    const SessionContext ctx = pair_context(a, b);
    LM_CHECK(run_handshake(w, I, R, a, b, ctx, ctx, Mutation{}).completed);
    const std::size_t baseline = g_live;
    const ByteView peer_b[1] = {b.ccs_view()};
    LM_CHECK_OK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1));
    LM_CHECK_OK(w.run(I, HsStep::M1Compose)); // an ephemeral private key now sits in a PSA slot
    g_destroy_failures = 1000;                // persistent driver fault
    LM_CHECK(I.cancel() == Status::RecoveryRequired);
    LM_CHECK(I.teardown_failed() && !I.idle());
    LM_CHECK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1) == Status::RecoveryRequired);
    LM_CHECK(k_heap_accounting ? g_live > baseline : true); // the slot really is still allocated
    g_destroy_failures = 0;                                   // the fault clears
    LM_CHECK_OK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1)); // retry freed it
    LM_CHECK(!I.teardown_failed());
    LM_CHECK(I.cancel() == Status::Ok);
    release_stuck();
    LM_CHECK_HEAP_EQ(g_live, baseline);
    // A single transient failure is absorbed by the retry inside the same teardown.
    LM_CHECK_OK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1));
    LM_CHECK_OK(w.run(I, HsStep::M1Compose));
    g_destroy_failures = 1;
    LM_CHECK(I.cancel() == Status::Ok && I.idle());
    release_stuck();
    LM_CHECK_HEAP_EQ(g_live, baseline);
}

LM_TEST("FIX1-22 a local PSA hash failure is a local fault, not the peer's rejection") {
    LM_CHECK_OK(crypto_init());
    Identity a, b;
    make_identity(a, "node-a");
    make_identity(b, "node-b");
    Worker w;
    HandshakeSlot I, R;
    const ByteView peer_a[1] = {a.ccs_view()};
    const ByteView peer_b[1] = {b.ccs_view()};
    // The failure is injected into each step in turn (msg 1..4, both roles): a local hash fault may
    // surface as NoCapacity/RecoveryRequired, but never as the peer failing authentication.
    for (int fail_at = 0; fail_at < 8; ++fail_at) {
        LM_CHECK_OK(I.begin(HsRole::Initiator, a.key, a.ccs_view(), peer_b, 1));
        LM_CHECK_OK(R.begin(HsRole::Responder, b.key, b.ccs_view(), peer_a, 1));
        Status st = Status::Ok;
        int n = 0;
        auto step = [&](HandshakeSlot &slot, HsStep s, ByteView in = ByteView{}) {
            if (st != Status::Ok) {
                return;
            }
            g_hash_update_fails = n++ == fail_at;
            st = w.run(slot, s, in);
            g_hash_update_fails = false;
        };
        step(I, HsStep::M1Compose);
        step(R, HsStep::M1Process, I.output());
        step(R, HsStep::M2Compose);
        step(I, HsStep::M2Process, R.output());
        step(I, HsStep::M3Compose);
        step(R, HsStep::M3Process, I.output());
        step(R, HsStep::M4Compose);
        step(I, HsStep::M4Process, R.output());
        LM_CHECK(st != Status::AuthRejected);
        (void)I.cancel();
        (void)R.cancel();
    }
}

// ================================ resource measurement ==========================================

namespace {

// A real worker thread on a stack we own and painted, so the deepest job body is measurable. This
// is the shape of the IDF worker (one thread, jobs handed over one at a time).
struct ThreadWorker {
    static constexpr std::size_t k_stack = 256 * 1024;
    uint8_t *stack = nullptr;
    pthread_t thread{};
    pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
    void *arg = nullptr;
    bool quit = false;
    bool done = true;
    Status result = Status::Ok;
    sim::SimStore store{sim::StoreGeometry{}};

    static void *main_loop(void *p) {
        auto *self = static_cast<ThreadWorker *>(p);
        pthread_mutex_lock(&self->mu);
        for (;;) {
            while (self->done && !self->quit) {
                pthread_cond_wait(&self->cv, &self->mu);
            }
            if (self->quit) {
                break;
            }
            port::JobEnv env{self->store};
            self->result = HandshakeSlot::run_job(env, self->arg);
            self->done = true;
            pthread_cond_broadcast(&self->cv);
        }
        pthread_mutex_unlock(&self->mu);
        return nullptr;
    }

    void start() {
        // mmap, not malloc: the heap accounting must not see the worker's own stack.
        stack = static_cast<uint8_t *>(mmap(nullptr, k_stack, PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        std::memset(stack, 0xA5, k_stack);
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstack(&attr, stack, k_stack);
        pthread_create(&thread, &attr, &ThreadWorker::main_loop, this);
        pthread_attr_destroy(&attr);
    }
    Status run(HandshakeSlot &slot, HsStep step, ByteView in = ByteView{}) {
        Status st = slot.prepare(step, in);
        if (st != Status::Ok) {
            return st;
        }
        pthread_mutex_lock(&mu);
        arg = &slot;
        done = false;
        pthread_cond_broadcast(&cv);
        while (!done) {
            pthread_cond_wait(&cv, &mu);
        }
        const Status job = result;
        pthread_mutex_unlock(&mu);
        return slot.complete(job);
    }
    std::size_t peak_stack() const {
        std::size_t untouched = 0;
        while (untouched < k_stack && stack[untouched] == 0xA5) {
            ++untouched;
        }
        return k_stack - untouched;
    }
    void stop() {
        pthread_mutex_lock(&mu);
        quit = true;
        pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&mu);
        pthread_join(thread, nullptr);
        munmap(stack, k_stack);
    }
};

} // namespace

LM_TEST("measure: worker stack and PSA heap peak of one full handshake (software model)") {
    LM_CHECK_OK(crypto_init());
    Identity a, b;
    make_identity(a, "node-a");
    make_identity(b, "node-b");
    Worker warm;
    HandshakeSlot *I = new HandshakeSlot();
    HandshakeSlot *R = new HandshakeSlot();
    const SessionContext ctx = pair_context(a, b);
    LM_CHECK(run_handshake(warm, *I, *R, a, b, ctx, ctx, Mutation{}).completed); // PSA warm-up

    ThreadWorker tw;
    tw.start();
    const std::size_t heap_before = g_live;
    g_peak = g_live;
    const ByteView pa[1] = {a.ccs_view()};
    const ByteView pb[1] = {b.ccs_view()};
    LM_CHECK_OK(I->begin(HsRole::Initiator, a.key, a.ccs_view(), pb, 1));
    LM_CHECK_OK(R->begin(HsRole::Responder, b.key, b.ccs_view(), pa, 1));
    std::size_t per_step_peak[9] = {};
    auto step = [&](HandshakeSlot &s, HsStep st, ByteView in, int idx) {
        LM_CHECK_OK(tw.run(s, st, in));
        per_step_peak[idx] = g_peak - heap_before;
    };
    step(*I, HsStep::M1Compose, ByteView{}, 0);
    step(*R, HsStep::M1Process, I->output(), 1);
    step(*R, HsStep::M2Compose, ByteView{}, 2);
    step(*I, HsStep::M2Process, R->output(), 3);
    step(*I, HsStep::M3Compose, ByteView{}, 4);
    step(*R, HsStep::M3Process, I->output(), 5);
    step(*R, HsStep::M4Compose, ByteView{}, 6);
    step(*I, HsStep::M4Process, R->output(), 7);
    LM_CHECK_OK(I->set_context(ctx));
    LM_CHECK_OK(R->set_context(ctx));
    step(*I, HsStep::Export, ByteView{}, 8);
    step(*R, HsStep::Export, ByteView{}, 8);
    const std::size_t stack_peak = tw.peak_stack();
    const std::size_t heap_peak = g_peak - heap_before;
    RecordKeys k;
    LM_CHECK_OK(I->take_keys(k));
    LM_CHECK_OK(R->take_keys(k));
    LM_CHECK_HEAP_EQ(g_live, heap_before); // every PSA key slot and bignum released
    tw.stop();
    std::printf("  [measure] worker stack peak (deepest job body, incl. thread start): %zu bytes\n",
                stack_peak);
    if (k_heap_accounting) {
        std::printf("  [measure] PSA heap peak above idle during a handshake: %zu bytes (live after: +0)\n",
                    heap_peak);
    } else {
        std::printf("  [measure] heap accounting off in this build (sanitizers); stack peak inflated\n");
    }
    std::printf("  [measure] sizeof(HandshakeSlot)=%zu sizeof(RecordSession)=%zu edhoc_context=%zu\n",
                sizeof(HandshakeSlot), sizeof(RecordSession),
                lm_edhoc_context_size());
    delete I;
    delete R;
    if (k_heap_accounting) {
        LM_CHECK(stack_peak < 16 * 1024); // regression guard, not a budget claim
    }
}

LM_TEST_MAIN()
