// Foundation types: codecs, bounded containers, handles, time domains, generation rules.
#include <cstdint>

#include "core/codec.hpp"
#include "core/events.hpp"
#include "core/ids.hpp"
#include "core/pool.hpp"
#include "core/result.hpp"
#include "core/ring.hpp"
#include "core/time.hpp"
#include "core/wire/cbor.hpp"
#include "gen/golden.hpp"
#include "lmtest.hpp"

using namespace lm;

LM_TEST("big-endian writer/reader round trip and sticky overrun") {
    std::array<uint8_t, 15> buf{};
    Writer w{MutByteView{buf}};
    w.u8(0xAB);
    w.u16be(0x0102);
    w.u32be(0x03040506);
    w.u64be(0x0708090A0B0C0D0EULL);
    LM_CHECK_OK(w.finish());
    LM_CHECK_EQ(w.size(), 15u);
    LM_CHECK_EQ(buf[1], 0x01u);
    LM_CHECK_EQ(buf[14], 0x0Eu);
    w.u8(1); // overflow
    LM_CHECK(w.finish() == Status::NoCapacity);

    Reader r{ByteView{buf}};
    LM_CHECK_EQ(r.u8(), 0xABu);
    LM_CHECK_EQ(r.u16be(), 0x0102u);
    LM_CHECK_EQ(r.u32be(), 0x03040506u);
    LM_CHECK_EQ(r.u64be(), 0x0708090A0B0C0D0EULL);
    LM_CHECK_OK(r.finish());
    LM_CHECK_EQ(r.u8(), 0u); // past the end: error, zero
    LM_CHECK(!r.ok());
    LM_CHECK(r.finish() == Status::BadFrame);
}

LM_TEST("reader rejects trailing bytes") {
    std::array<uint8_t, 3> buf{1, 2, 3};
    Reader r{ByteView{buf}};
    (void)r.u16be();
    LM_CHECK(r.finish() == Status::BadFrame);
}

LM_TEST("span subspan is bounds checked") {
    std::array<uint8_t, 4> buf{1, 2, 3, 4};
    ByteView v{buf};
    LM_CHECK_EQ(v.subspan(2, 2).size(), 2u);
    LM_CHECK(v.subspan(3, 2).empty());
    LM_CHECK(v.subspan(5, 0).empty());
    std::array<uint8_t, 2> small{};
    LM_CHECK(copy_bytes(MutByteView{small}, v) == Status::NoCapacity);
}

LM_TEST("R10 pool generation: stale handle cannot reach the next occupant") {
    Pool<int, 2> pool;
    const Handle a = pool.acquire();
    LM_CHECK(!a.is_none());
    *pool.get(a) = 7;
    LM_CHECK(pool.release(a));
    const Handle b = pool.acquire(); // same index, new generation
    LM_CHECK_EQ(b.index, a.index);
    LM_CHECK(b.generation != a.generation);
    LM_CHECK(pool.get(a) == nullptr);
    LM_CHECK(!pool.release(a)); // double release detected
    LM_CHECK(pool.get(b) != nullptr);
    (void)pool.acquire();
    LM_CHECK(pool.acquire().is_none()); // full: caller reports NO_CAPACITY
}

LM_TEST("FIX1-25 pool slot with an exhausted generation is retired, an ancient handle never revalidates") {
    Pool<int, 2> pool;
    pool.seed_generation_for_test(0, UINT32_MAX - 1);
    const Handle old = pool.acquire(); // slot 0, generation UINT32_MAX - 1
    LM_CHECK_EQ(old.index, 0u);
    LM_CHECK(pool.release(old));
    const Handle last = pool.acquire(); // generation UINT32_MAX: the final use of slot 0
    LM_CHECK_EQ(last.index, 0u);
    LM_CHECK_EQ(last.generation, UINT32_MAX);
    LM_CHECK(pool.release(last));
    LM_CHECK(pool.retired(0));
    LM_CHECK(pool.get(last) == nullptr && pool.get(old) == nullptr);
    // A wrapped generation (1) would have matched a handle from 4e9 releases ago; slot 0 is gone.
    const Handle next = pool.acquire();
    LM_CHECK_EQ(next.index, 1u);
    LM_CHECK(pool.acquire().is_none()); // capacity shrank by one instead of reusing slot 0
    LM_CHECK(pool.get(Handle{0, 1}) == nullptr);
}

LM_TEST("bounded queue refuses when full") {
    BoundedQueue<int, 2> q;
    LM_CHECK(q.push(1));
    LM_CHECK(q.push(2));
    LM_CHECK(!q.push(3));
    int v = 0;
    LM_CHECK(q.pop(v));
    LM_CHECK_EQ(v, 1);
}

LM_TEST("spsc ring counts drops") {
    SpscRing<int, 2> r;
    LM_CHECK(r.push(1));
    LM_CHECK(r.push(2));
    LM_CHECK(!r.push(3));
    LM_CHECK_EQ(r.dropped(), 1u);
    int v = 0;
    LM_CHECK(r.pop(v) && v == 1);
}

LM_TEST("spsc ring of a capacity that is not a power of two: FIFO across many wraps, full is full") {
    SpscRing<int, 5> r;
    int next_in = 0;
    int next_out = 0;
    for (int round = 0; round < 50; ++round) {
        const int fill = 1 + round % 5; // 1..5 items per round: every index phase is visited
        for (int i = 0; i < fill; ++i) {
            LM_CHECK(r.push(next_in++));
        }
        if (fill == 5) {
            LM_CHECK(!r.push(-1)); // exactly N fit
        }
        int v = 0;
        for (int i = 0; i < fill; ++i) {
            LM_CHECK(r.pop(v) && v == next_out++);
        }
        LM_CHECK(!r.pop(v));
    }
    LM_CHECK_EQ(r.dropped(), 10u);
}

LM_TEST("app event queue reports a gap instead of blocking the owner") {
    AppEventQueue<3> q;
    lm_event_t ev{};
    ev.kind = LM_EVENT_MESSAGE;
    LM_CHECK(q.push(ev));
    LM_CHECK(q.push(ev));
    LM_CHECK(q.push(ev));
    LM_CHECK(!q.push(ev)); // lost: the owner does not wait for the application
    lm_event_t out{};
    LM_CHECK(q.pop(out) && out.kind == LM_EVENT_MESSAGE);
    LM_CHECK(!q.push(ev)); // one free slot is reserved for the GAP marker, event lost too
    LM_CHECK(q.pop(out) && out.kind == LM_EVENT_MESSAGE);
    LM_CHECK(q.push(ev)); // GAP then this event
    LM_CHECK(q.pop(out) && out.kind == LM_EVENT_MESSAGE);
    LM_CHECK(q.pop(out) && out.kind == LM_EVENT_GAP);
    LM_CHECK(q.pop(out) && out.kind == LM_EVENT_MESSAGE);
    LM_CHECK(!q.pop(out));
    LM_CHECK(q.push(ev));
    LM_CHECK(q.pop(out) && out.kind == LM_EVENT_MESSAGE && out.event_sequence == 6u);
}

LM_TEST("generations never wrap") {
    RootTerm t{0xFFFFFFFEu};
    RootTerm next;
    LM_CHECK(next_generation(t, 0xFFFFFFFFu, next));
    LM_CHECK_EQ(next.value(), 0xFFFFFFFFu);
    LM_CHECK(!next_generation(next, 0xFFFFFFFFu, next));
    MembershipGen m{k_u63_max};
    LM_CHECK(!next_generation(m, k_u63_max, m));
}

LM_TEST("deadline check: TIME_UNCERTAIN unless provable") {
    const RootTime deadline{RootTerm{3}, 10000};
    LM_CHECK(check_deadline(RootTimeBound{RootTerm{3}, 5000, 9000, true}, deadline) ==
             DeadlineCheck::Before);
    LM_CHECK(check_deadline(RootTimeBound{RootTerm{3}, 10000, 12000, true}, deadline) ==
             DeadlineCheck::After);
    LM_CHECK(check_deadline(RootTimeBound{RootTerm{3}, 9000, 11000, true}, deadline) ==
             DeadlineCheck::Uncertain);
    LM_CHECK(check_deadline(RootTimeBound{RootTerm{4}, 1, 2, true}, deadline) ==
             DeadlineCheck::Uncertain); // another root term
    LM_CHECK(check_deadline(RootTimeBound{}, deadline) == DeadlineCheck::Uncertain);
}

LM_TEST("monotonic time saturates") {
    LM_CHECK(MonoTime::never() + Duration::from_s(1) == MonoTime::never());
    LM_CHECK((MonoTime{5} + Duration{-10}).us == 0u);
    LM_CHECK(earliest(MonoTime{3}, MonoTime::never()).us == 3u);
}

LM_TEST("result carries value or error") {
    Result<int> ok{5};
    LM_CHECK(ok.ok() && ok.value() == 5);
    Result<int> err{Status::NoRoute};
    LM_CHECK(!err.ok() && err.status() == Status::NoRoute);
}

// The session-context CBOR of tests/golden.json is rebuilt field by field with CborWriter.
LM_TEST("deterministic CBOR writer reproduces the golden session context") {
    const auto golden = lmtest::from_hex(gen::golden::k_frames[0].link_context_hex);
    LM_CHECK_EQ(golden.size(), 180u);
    const ByteView g{golden.data(), golden.size()};
    std::array<uint8_t, 256> buf{};
    wire::CborWriter w{MutByteView{buf}};
    w.array(12);
    w.text(wire::ascii("LM1"));
    w.uint(1);                  // purpose: neighbor link
    w.bytes(g.subspan(7, 16));  // fleet id
    w.bytes(g.subspan(24, 16)); // domain id
    w.bytes(g.subspan(42, 32)); // initiator DeviceId
    w.bytes(g.subspan(76, 32)); // responder DeviceId
    w.uint(1);
    w.uint(1);
    w.uint(1);
    w.uint(1);
    w.bytes(g.subspan(114, 32)); // credential hash i
    w.bytes(g.subspan(148, 32)); // credential hash r
    LM_CHECK_OK(w.finish());
    LM_CHECK(bytes_equal(w.written(), g));
}

LM_TEST("CBOR writer uses shortest heads") {
    std::array<uint8_t, 32> buf{};
    wire::CborWriter w{MutByteView{buf}};
    w.uint(23);
    w.uint(24);
    w.uint(256);
    w.uint(65536);
    w.uint(0x100000000ULL);
    w.integer(-1);
    w.integer(-7); // COSE alg ES256
    LM_CHECK_OK(w.finish());
    const auto want = lmtest::from_hex("1718181901001a000100001b00000001000000002026");
    LM_CHECK(bytes_equal(w.written(), ByteView{want.data(), want.size()}));
}

LM_TEST_MAIN()
