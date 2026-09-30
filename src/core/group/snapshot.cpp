// GroupSnapshotV2 (docs/22 §2, protocol/control.cddl 32/33): the origin fetches a fixed target set from
// the root page by page; the root serves signed pages of a snapshot it fixed at page 0. The snapshot hash
// covers domain, group, revision, token, origin and the whole sorted target list, never one page. The
// P-256 work (signing a page on the root, verifying it at the origin) is one worker job at a time;
// its 1 KiB of memory is the exchange's lent scratch, so a handshake is refused meanwhile (Busy), never
// blamed on the peer.
#include <algorithm>
#include <cstring>

#include "core/engine.hpp"
#include "core/group/group.hpp"
#include "core/member/credentials.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "core/wire/control.hpp"
#include "security/crypto.hpp"

namespace lm::group {
namespace {
constexpr uint64_t k_u32_max = 0xFFFFFFFFULL; // group_id is a u32
constexpr uint8_t k_cose_tag = 0xD2; // CBOR tag 18: a COSE_Sign1 (the signed page); a session body starts 0x87
} // namespace

Status Fanout::snapshot_hash(const Op &g, Sha256Digest &out) const {
    struct Ctx {
        const Fanout *f;
        const Op *g;
        DeviceId origin;
        std::array<uint8_t, 96> buf;
    } c{this, &g, g.kind == Op::Kind::Served ? g.origin : engine_.identity().self(), {}};
    return sec::sha256_chunks(
        [](void *p, std::size_t i) -> ByteView {
            auto &x = *static_cast<Ctx *>(p);
            wire::CborWriter w{MutByteView{x.buf}};
            if (i == 0) {
                w.array(6);
                w.bytes(x.f->engine_.identity().delegation().domain.view());
                w.uint(x.g->group_id);
                w.uint(x.g->revision);
                w.bytes(ByteView{x.g->token});
                w.bytes(x.origin.view());
                w.array(x.g->total);
            } else {
                DeviceId d;
                if (!x.f->device_at(*x.g, i - 1, d)) {
                    return ByteView{};
                }
                w.array(3);
                w.bytes(d.view());
                w.uint(x.g->t[i - 1].assignment);
                w.uint(x.g->t[i - 1].membership);
            }
            return w.finish() == Status::Ok ? w.written() : ByteView{};
        },
        &c, static_cast<std::size_t>(g.total) + 1U, out);
}

// The page boundaries are a pure function of the snapshot (rows in order, at most k_page rows and k_row_bytes of
// encoding per page), so the root can serve any page by number and the origin needs only the number.
void Fanout::page_span(const Op &g, unsigned page, std::size_t &first, std::size_t &n) {
    auto width = [](uint64_t v) { return v < 24 ? 1U : (v < 256 ? 2U : (v < 65536 ? 3U : (v <= 0xFFFFFFFFULL ? 5U : 9U))); };
    first = 0;
    n = 0;
    for (unsigned p = 0; p <= page; ++p) {
        first += n;
        n = 0;
        std::size_t bytes = 0;
        while (first + n < g.total && n < k_page) {
            const Target &t = g.t[first + n];
            const std::size_t row = 35U + width(t.assignment) + width(t.membership); // array(3), bstr(32), two uints
            if (n != 0 && bytes + row > k_row_bytes) {
                break;
            }
            bytes += row;
            ++n;
        }
    }
    if (first >= g.total && !(page == 0 && g.total == 0)) {
        n = 0;
    }
}

// ---- origin: fetch ----
void Fanout::request_page(Op &g, MonoTime now) {
    if (job_ != Job::None && &ops_[job_op_] == &g) {
        g.at = now + k_fetch_rto; // a page of this snapshot is being verified
        return;
    }
    const member::LocalIdentity &id = engine_.identity();
    const unsigned page = g.pages;
    std::array<uint8_t, 64> data{};
    wire::CborWriter d{MutByteView{data}};
    d.array(4);
    d.uint(g.group_id);
    d.uint(g.revision);
    d.uint(page);
    if (page == 0) {
        d.null(); // page 0 opens a new snapshot; the later pages name its token
    } else {
        d.bytes(ByteView{g.token});
    }
    wire::ControlBody b;
    b.type = k_type_request;
    b.request_id = g.req;
    b.domain = id.delegation().domain.bytes;
    b.issuer = id.self().bytes;
    b.data = d.written();
    std::array<uint8_t, 160> body{};
    std::size_t n = 0;
    if (d.finish() != Status::Ok || wire::encode_control_body(b, MutByteView{body}, n) != Status::Ok) {
        fetch_failed(g, static_cast<uint32_t>(Status::InvalidArgument));
        return;
    }
    const delivery::ControlSendRequest cr{id.delegation().root, g.term, g.expires};
    const Reply r = engine_.delivery().send_control(cr, ByteView{body.data(), n}, now);
    if (r.status == Status::Ok) {
        ++g.tries;
        g.at = now + k_fetch_rto; // repeated with the same request id if no page comes back
    } else if (r.status == Status::Expired) {
        g.outcome = LM_OUTCOME_EXPIRED;
        g.reason = static_cast<uint32_t>(r.status);
        end(g);
    } else {
        g.at = now + Duration::from_ms(500); // the control lane is busy or the root is not reachable yet
    }
}

void Fanout::fetch_failed(Op &g, uint32_t reason) {
    g.total = 0; // nothing was dispatched: no target exists to hold an outcome
    g.got = 0;
    g.outcome = LM_OUTCOME_REJECTED;
    g.reason = reason;
    end(g);
}

// A control object arrived: a signed page for an operation that is fetching, or a request to serve.
void Fanout::on_control(const DeviceId &origin, ByteView payload, MonoTime now) {
    if (payload.empty()) {
        return;
    }
    if (payload[0] == k_cose_tag) {
        on_page(payload, now);
        return;
    }
    wire::ControlBody b;
    if (wire::decode_control_body(payload, wire::ControlCarrier::Session, b) == Status::Ok &&
        b.type == k_type_request) {
        serve(origin, b, now);
    }
}

void Fanout::on_page(ByteView cose, MonoTime now) {
    if (root_origin()) {
        return; // the root is the origin of its own operations: it never fetches a snapshot
    }
    member::Envelope env;
    ByteView data;
    const member::LocalIdentity &id = engine_.identity();
    if (member::peek_signed(cose, k_type_snapshot, env, data) != Status::Ok || env.issuer != id.delegation().root) {
        return; // only the root serves snapshots
    }
    Op *g = nullptr;
    for (Op &x : ops_) {
        g = x.kind == Op::Kind::Own && x.st == Op::St::Fetching && x.req == env.request.bytes ? &x : g;
    }
    if (g == nullptr || job_ != Job::None) {
        return; // stale, or the worker is busy: the request is repeated
    }
    scratch_ = engine_.link().exchange().lend_scratch();
    if (scratch_.size() < cose.size() || scratch_.empty()) {
        release_scratch();
        return;
    }
    std::memcpy(scratch_.data(), cose.data(), cose.size());
    cose_len_ = cose.size();
    page_.root_key = id.delegation().key;
    if (submit(Job::Verify, *g, now) != Status::Ok) {
        release_scratch();
    }
}

void Fanout::accept_page(Op &g, ByteView cose, MonoTime now) {
    member::Envelope env;
    ByteView data;
    if (member::peek_signed(cose, k_type_snapshot, env, data) != Status::Ok || env.request.bytes != g.req) {
        return;
    }
    wire::CborReader r{data};
    (void)r.array(8, 8);
    const uint64_t gid = r.uint_in(0, k_u32_max);
    const uint64_t rev = r.uint_in(0, k_u63_max);
    const ByteView token = r.bstr(16, 16);
    const ByteView origin = r.bstr(32, 32);
    const uint64_t total = r.uint_in(0, k_max_targets);
    const uint64_t page = r.uint_in(0, k_snap_pages - 1);
    const ByteView hash = r.bstr(32, 32);
    const std::size_t n = r.array(0, k_page);
    const unsigned want = g.pages;
    const std::size_t left = total > g.got ? total - g.got : 0;
    const bool same = g.got == 0 || (total == g.total && std::equal(token.begin(), token.end(), g.token.begin()) &&
                                     std::equal(hash.begin(), hash.end(), g.hash.begin()));
    if (!r.ok() || page < want) {
        return; // malformed (the signature covers it, so this is the root's bug) or a repeated page
    }
    if (gid != g.group_id || rev != g.revision || page != want || (left == 0 ? n != 0 : (n == 0 || n > left)) || !same ||
        !std::equal(origin.begin(), origin.end(), engine_.identity().self().bytes.begin())) {
        fetch_failed(g, static_cast<uint32_t>(Status::BadFrame));
        return;
    }
    if (g.got == 0) {
        g.total = static_cast<uint8_t>(total);
        std::copy(token.begin(), token.end(), g.token.begin());
        std::copy(hash.begin(), hash.end(), g.hash.begin());
    }
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t i = g.got + k;
        (void)r.array(3, 3);
        const ByteView dev = r.bstr(32, 32);
        const uint64_t a = r.uint_in(0, k_u63_max);
        const uint64_t m = r.uint_in(0, k_u63_max);
        if (!r.ok()) {
            break;
        }
        DeviceId *ids = ids_of(g);
        std::copy(dev.begin(), dev.end(), ids[i].bytes.begin());
        g.t[i] = Target();
        g.t[i].assignment = a;
        g.t[i].membership = m;
        if (i > 0 && !(ids[i - 1] < ids[i])) {
            r.fail(); // sorted and unique, or the set is not the one that was hashed
        }
    }
    Sha256Digest h{};
    if (r.finish() != Status::Ok) {
        fetch_failed(g, static_cast<uint32_t>(Status::BadFrame));
        return;
    }
    g.got = static_cast<uint8_t>(g.got + n);
    ++g.pages;
    ++stats_.pages_fetched;
    if (g.got < g.total) {
        engine_.random(MutByteView{g.req});
        g.tries = 0;
        request_page(g, now);
        return;
    }
    if (snapshot_hash(g, h) != Status::Ok || h != g.hash) {
        fetch_failed(g, static_cast<uint32_t>(Status::AuthRejected)); // the pages do not add up to the hash
        return;
    }
    begin(g, now);
}

// ---- root: serve ----
void Fanout::serve(const DeviceId &origin, const wire::ControlBody &b, MonoTime now) {
    if (engine_.config().role != Role::Root || !engine_.groups().allowed(origin)) {
        return; // only a member of this domain gets a snapshot, and it is that member's own (docs/19 §8)
    }
    wire::CborReader r{b.data};
    (void)r.array(4, 4);
    const auto gid = static_cast<uint32_t>(r.uint_in(0, k_u32_max));
    const uint64_t rev = r.uint_in(0, k_u63_max);
    const auto page = static_cast<unsigned>(r.uint_in(0, k_snap_pages - 1));
    const bool named = !r.try_null();
    const ByteView token = named ? r.bstr(16, 16) : ByteView{};
    if (r.finish() != Status::Ok) {
        return;
    }
    Op *s = nullptr;
    for (Op &x : ops_) {
        if (x.kind != Op::Kind::Served || x.origin != origin || x.group_id != gid || x.revision != rev) {
            continue;
        }
        s = (named ? std::equal(token.begin(), token.end(), x.token.begin()) : (x.req == b.request_id)) ? &x : s;
    }
    if (!named) {
        if (page != 0) {
            return;
        }
        if (s == nullptr) { // a new snapshot: the set is fixed here, once
            std::size_t served = 0;
            for (Op &x : ops_) {
                if (x.kind == Op::Kind::Served && x.origin == origin && !(job_ != Job::None && &ops_[job_op_] == &x)) {
                    reset_op(x); // one snapshot per origin: a member cannot fill the pool by asking again
                }
                served += x.kind == Op::Kind::Served ? 1U : 0U;
            }
            if (served + 1 >= k_ops || (s = alloc(Op::Kind::Served)) == nullptr) {
                return; // at most k_ops - 1 held for others (the root's own operations keep a slot); silence = timeout
            }
            s->group_id = gid;
            s->revision = rev;
            s->origin = origin;
            s->req = b.request_id;
            s->at = now + k_snapshot_life;
            engine_.random(MutByteView{s->token});
            if (engine_.groups().snapshot(gid, rev, *s, ids_of(*s)) != Status::Ok || snapshot_hash(*s, s->hash) != Status::Ok) {
                reset_op(*s);
                return;
            }
        }
    } else if (s == nullptr || now >= s->at) {
        return; // unknown, other origin's, or expired (120 s)
    }
    std::size_t first = 0;
    std::size_t rows = 0;
    page_span(*s, page, first, rows);
    if (s->total == 0 ? page != 0 : rows == 0) {
        return; // no such page
    }
    sign_page(*s, page, b.request_id, now);
}

void Fanout::sign_page(Op &s, unsigned page, const std::array<uint8_t, 16> &req, MonoTime now) {
    if (job_ != Job::None) {
        return; // the origin repeats its request
    }
    scratch_ = engine_.link().exchange().lend_scratch();
    if (scratch_.empty()) {
        return;
    }
    const member::LocalIdentity &id = engine_.identity();
    Page &p = page_;
    std::size_t first = 0;
    std::size_t rows = 0;
    page_span(s, page, first, rows);
    p.n = static_cast<uint8_t>(rows);
    bool ok = p.n <= k_serve_rows;
    for (std::size_t k = 0; k < p.n && ok; ++k) {
        const Target &t = s.t[first + k];
        ok = device_at(s, first + k, p.dev[k]);
        p.a[k] = t.assignment;
        p.m[k] = t.membership;
    }
    p.req = req;
    p.token = s.token;
    p.hash = s.hash;
    p.domain = id.delegation().domain;
    p.issuer = id.self();
    p.origin = s.origin;
    p.key = id.key();
    p.revision = s.revision;
    p.group_id = s.group_id;
    p.total = s.total;
    p.page = static_cast<uint8_t>(page);
    if (!ok || submit(Job::Sign, s, now) != Status::Ok) {
        release_scratch(); // no page, the origin times out
    }
}

void Fanout::send_page(Op &s, MonoTime now) {
    delivery::Delivery &dv = engine_.delivery();
    const RootTimeBound b = dv.root_time(now);
    if (!b.valid) {
        return;
    }
    const delivery::ControlSendRequest cr{s.origin, b.term.value(), b.latest_ms + 30000};
    if (dv.send_control(cr, ByteView{scratch_.data(), cose_len_}, now).status == Status::Ok) {
        ++stats_.pages_served;
    }
}

// ---- the worker job ----
Status Fanout::submit(Job kind, const Op &g, MonoTime) {
    job_ = kind; // set before the worker can read it
    job_op_ = static_cast<uint32_t>(&g - ops_.data());
    const Status s = engine_.submit_job(JobOwner::Group, Handle{static_cast<uint16_t>(job_op_), g.generation},
                                        JobClass::PublicKey, &job_body, this);
    if (s != Status::Ok) {
        job_ = Job::None;
    }
    return s;
}

// Worker. Reads only the copies made on the owner (page_, the scratch); writes only cose_len_ and the scratch.
Status Fanout::job_body(port::JobEnv &, void *arg) {
    auto &f = *static_cast<Fanout *>(arg);
    const Page &p = f.page_;
    if (f.job_ == Job::Verify) {
        member::Envelope env;
        ByteView data;
        return member::open_signed(ByteView{f.scratch_.data(), f.cose_len_}, p.root_key, k_type_snapshot, env, data);
    }
    std::array<uint8_t, 1024> buf{};
    wire::CborWriter w{MutByteView{buf}};
    w.array(8);
    w.uint(p.group_id);
    w.uint(p.revision);
    w.bytes(ByteView{p.token});
    w.bytes(p.origin.view());
    w.uint(p.total);
    w.uint(p.page);
    w.bytes(ByteView{p.hash});
    w.array(p.n);
    for (std::size_t k = 0; k < p.n; ++k) {
        w.array(3);
        w.bytes(p.dev[k].view());
        w.uint(p.a[k]);
        w.uint(p.m[k]);
    }
    LM_TRY(w.finish());
    member::Envelope env;
    env.type = k_type_snapshot;
    env.request.bytes = p.req;
    env.domain = p.domain;
    env.revision = p.revision;
    env.issuer = p.issuer;
    return member::issue_signed(p.key, env, w.written(), f.scratch_, f.cose_len_);
}

void Fanout::on_job_done(Handle slot, Status s, MonoTime now) {
    const Job kind = job_;
    job_ = Job::None;
    Op &g = ops_[slot.index < ops_.size() ? slot.index : 0];
    const bool mine = slot.index < ops_.size() && g.generation == slot.generation && g.kind != Op::Kind::Free;
    if (mine && kind == Job::Sign && s == Status::Ok) {
        send_page(g, now);
    } else if (mine && kind == Job::Verify && g.st == Op::St::Fetching) {
        if (s == Status::Ok) {
            accept_page(g, ByteView{scratch_.data(), cose_len_}, now);
        } else {
            fetch_failed(g, static_cast<uint32_t>(Status::AuthRejected));
        }
    }
    release_scratch();
}

void Fanout::release_scratch() {
    if (!scratch_.empty()) {
        engine_.link().exchange().return_scratch();
        scratch_ = MutByteView{};
    }
}

} // namespace lm::group
