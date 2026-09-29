#include "core/channel/wire.hpp"

#include "core/codec.hpp"
#include "core/wire/cbor.hpp"
#include "security/crypto.hpp"

namespace lm::channel {
namespace {

bool valid_channel(uint8_t c) { return c >= 1 && c <= 13; }

// The two directions of one layout: io(f, record) lists the fields once, Put writes them, Get reads them.
struct Put {
    Writer w;
    void u8(uint8_t &v) { w.u8(v); }
    void u16(uint16_t &v) { w.u16be(v); }
    void u32(uint32_t &v) { w.u32be(v); }
    void u64(uint64_t &v) { w.u64be(v); }
    template <std::size_t N> void raw(std::array<uint8_t, N> &v) { w.bytes(ByteView{v}); }
    template <class T> void tag(T &t) { w.u32be(t.value()); } // RootTerm, ChannelEpoch
    template <class E> void en(E &e) { w.u8(static_cast<uint8_t>(e)); }
};
struct Get {
    Reader r;
    void u8(uint8_t &v) { v = r.u8(); }
    void u16(uint16_t &v) { v = r.u16be(); }
    void u32(uint32_t &v) { v = r.u32be(); }
    void u64(uint64_t &v) { v = r.u64be(); }
    template <std::size_t N> void raw(std::array<uint8_t, N> &v) { r.copy_to(v); }
    template <class T> void tag(T &t) { t = T{r.u32be()}; }
    template <class E> void en(E &e) { e = static_cast<E>(r.u8()); }
};

template <class F> void io(F &f, Plan &p) {
    f.raw(p.id.bytes);
    f.tag(p.term);
    f.tag(p.epoch);
    f.u8(p.old_ch);
    f.u8(p.new_ch);
    f.u64(p.switch_root_ms);
    f.u32(p.max_err_ms);
    f.u32(p.settle_ms);
    f.u64(p.policy_rev);
    f.raw(p.participants);
}
template <class F> void io(F &f, PlanRec &m) {
    f.en(m.phase);
    io(f, m.plan);
}
template <class F> void io(F &f, Receipt &m) {
    f.raw(m.id.bytes);
    f.raw(m.hash);
    f.en(m.evidence);
    f.u32(m.reason);
    f.u32(m.clock_err_ms);
}
template <class F> void io(F &f, TimeReq &m) {
    f.raw(m.nonce);
    f.tag(m.term);
    f.u64(m.t1_us);
}
template <class F> void io(F &f, TimeResp &m) {
    f.raw(m.nonce);
    f.tag(m.term);
    f.u64(m.t1_us);
    f.u64(m.t2_us);
    f.u64(m.t3_us);
}
template <class F> void io(F &f, State &m) {
    f.tag(m.epoch);
    f.u8(m.channel);
}
template <class F> void io(F &f, Survey &m) {
    f.u16(m.sid);
    f.en(m.role);
    f.u8(m.channel);
    f.u16(m.peer);
    f.u64(m.start_root_ms);
    f.u16(m.visit_ms);
    f.u16(m.tol_ms);
    f.u8(m.probes);
}
template <class F> void io(F &f, SurveyResult &m) {
    f.u16(m.sid);
    f.en(m.role);
    f.u8(m.status);
    f.u8(m.ok);
    f.u8(m.fail);
    f.u16(m.service_ms);
}
template <class F> void io(F &f, Degraded &m) {
    f.u32(m.loss_q16);
    f.u16(m.attempts);
}

// Range checks of what was read (a decoded field is never trusted).
bool valid(const PlanRec &m) { return static_cast<uint8_t>(m.phase) <= 2 && valid_plan(m.plan); }
bool valid(const Receipt &m) { return static_cast<uint8_t>(m.evidence) <= 3; }
bool valid(const TimeReq &) { return true; }
bool valid(const TimeResp &m) { return m.t3_us >= m.t2_us; }
bool valid(const State &m) { return valid_channel(m.channel); }
bool valid(const Survey &m) {
    return static_cast<uint8_t>(m.role) <= 1 && valid_channel(m.channel) && m.peer != 0 && m.peer != 0xFFFF && m.visit_ms >= 20 &&
           m.visit_ms <= 200 && m.tol_ms >= 5 && m.tol_ms <= 200 && m.probes >= 1 && m.probes <= 16;
}
bool valid(const SurveyResult &m) { return static_cast<uint8_t>(m.role) <= 1; }
bool valid(const Degraded &) { return true; }

} // namespace

bool is_record(ByteView body) { return !body.empty() && body[0] >= 0xE6 && body[0] <= 0xED; }
Op op_of(ByteView body) { return static_cast<Op>(body[0]); }

bool valid_plan(const Plan &p) {
    return valid_channel(p.old_ch) && valid_channel(p.new_ch) && p.old_ch != p.new_ch && p.epoch.value() != 0 &&
           p.switch_root_ms != 0 && p.max_err_ms >= 50 && p.max_err_ms <= 10000 && p.policy_rev <= k_u63_max;
}

void put_plan(Writer &w, const Plan &p) {
    Put f{w};
    Plan copy = p;
    io(f, copy);
    w = f.w;
}

Plan get_plan(Reader &r) {
    Get f{r};
    Plan p;
    io(f, p);
    r = f.r;
    return p;
}

// docs/19 §1: [plan_id, root_term, channel_epoch, old, new, participant_hash, switch_root_ms,
// max_clock_error_ms, settle_ms, policy_revision]; no phase, no hash.
Status plan_hash(const Plan &p, Sha256Digest &out) {
    std::array<uint8_t, 128> buf{};
    wire::CborWriter w{MutByteView{buf}};
    w.array(10);
    w.bytes(p.id.view());
    w.uint(p.term.value());
    w.uint(p.epoch.value());
    w.uint(p.old_ch);
    w.uint(p.new_ch);
    w.bytes(ByteView{p.participants});
    w.uint(p.switch_root_ms);
    w.uint(p.max_err_ms);
    w.uint(p.settle_ms);
    w.uint(p.policy_rev);
    LM_TRY(w.finish());
    return sec::sha256(w.written(), out);
}

template <class M> Status encode(const M &m, MutByteView out, std::size_t &len) {
    Put f{Writer{out}};
    f.w.u8(static_cast<uint8_t>(M::op));
    M copy = m;
    io(f, copy);
    len = f.w.size();
    return f.w.finish();
}

template <class M> Status decode(ByteView body, M &out) {
    if (body.empty() || body[0] != static_cast<uint8_t>(M::op)) {
        return Status::BadFrame;
    }
    Get f{Reader{body.from(1)}};
    io(f, out);
    return f.r.finish() == Status::Ok && valid(out) ? Status::Ok : Status::BadFrame;
}

#define LM_WIRE_RECORD(T) \
    template Status encode<T>(const T &, MutByteView, std::size_t &); \
    template Status decode<T>(ByteView, T &);
LM_WIRE_RECORD(PlanRec)
LM_WIRE_RECORD(Receipt)
LM_WIRE_RECORD(TimeReq)
LM_WIRE_RECORD(TimeResp)
LM_WIRE_RECORD(State)
LM_WIRE_RECORD(Survey)
LM_WIRE_RECORD(SurveyResult)
LM_WIRE_RECORD(Degraded)
#undef LM_WIRE_RECORD

} // namespace lm::channel
