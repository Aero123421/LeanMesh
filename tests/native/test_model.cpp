// S20 seeded model tests (docs/18 §2): random message / loss / link / reboot schedules run against the PRODUCTION
// delivery, link and journal code (real lm_context + Engine per node on simulated ports, TEST-ONLY fleet credentials)
// and the evidence invariants are checked after every step and at the end:
//   - an operation's evidence bits and outcome only ever move forward (APPLIED and REJECTED never change),
//   - APPLIED / APP_APPLIED exist only if the destination application reported APPLIED,
//   - a message reaches the destination application once unless that node restarted (then at most once per restart),
//   - END_RECEIVED / RECEIVED means the destination really has it (unless a volatile copy died with a restart),
//   - after the network is healed every operation with a finite deadline is finished: nothing stays open forever.
// A failure prints the seed, the event log and a minimised schedule (greedy step removal); re-run one seed with
// LM_MODEL_SEED=<n>, change the number of seeds with LM_MODEL_SEEDS=<n>. The reference machine is the production
// code of the commit printed with the failure, not a test-only model. Sim time only: protocol bench, no RF evidence.
#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "capi/context.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"

#ifndef LM_MODEL_COMMIT
#define LM_MODEL_COMMIT "unknown"
#endif

using namespace lm;
using namespace lm::sim;
namespace ev = lm::delivery::ev;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr unsigned k_nodes = 4;              // root 0 - 1 - 2 - 3 (a chain: every pair has a 1..3 hop route)
constexpr uint64_t k_root_ms0 = 1'000'000;
constexpr uint64_t k_ttl_ms = 120'000;

struct Rng { // xorshift64*: the schedule generator, independent of the simulator's own stream
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed) {
        for (int i = 0; i < 4; ++i) { // splitmix64 rounds: nearby seeds must not start on nearby states
            uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            s = z ^ (z >> 31);
        }
        s |= 1;
    }
    uint64_t next() {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        return s * 0x2545F4914F6CDD1DULL;
    }
    unsigned below(unsigned n) { return static_cast<unsigned>(next() % n); }
};

enum class Kind : uint8_t { Send, Run, Take, Apply, Loss, LinkDown, LinkUp, Reboot };
struct Step {
    Kind kind = Kind::Run;
    uint8_t a = 0;      // from / node / link index (link i joins node i and i+1)
    uint8_t b = 0;      // to
    uint8_t delivery = LM_RECEIVED;
    uint8_t storage = LM_VOLATILE;
    uint16_t value = 0; // run ms / loss permille
};

std::string describe(const Step &s) {
    char buf[96];
    switch (s.kind) {
    case Kind::Send:
        std::snprintf(buf, sizeof buf, "send %u->%u %s %s", s.a, s.b, s.delivery == LM_APPLIED ? "APPLIED" : "RECEIVED",
                      s.storage == LM_DURABLE ? "DURABLE" : "VOLATILE");
        break;
    case Kind::Run: std::snprintf(buf, sizeof buf, "run %u ms", s.value); break;
    case Kind::Take: std::snprintf(buf, sizeof buf, "app %u takes its events", s.a); break;
    case Kind::Apply: std::snprintf(buf, sizeof buf, "app %u reports APPLIED for what it holds", s.a); break;
    case Kind::Loss: std::snprintf(buf, sizeof buf, "link %u-%u loss %u permille", s.a, s.a + 1, s.value); break;
    case Kind::LinkDown: std::snprintf(buf, sizeof buf, "link %u-%u down", s.a, s.a + 1); break;
    case Kind::LinkUp: std::snprintf(buf, sizeof buf, "link %u-%u up", s.a, s.a + 1); break;
    case Kind::Reboot: std::snprintf(buf, sizeof buf, "power cut + restart of node %u", s.a); break;
    }
    return buf;
}

std::vector<Step> generate(uint64_t seed, unsigned count) {
    Rng r(seed);
    std::vector<Step> steps;
    for (unsigned i = 0; i < count; ++i) {
        Step s;
        const unsigned dice = r.below(100);
        if (dice < 34) {
            s.kind = Kind::Send;
            s.a = static_cast<uint8_t>(r.below(k_nodes));
            s.b = static_cast<uint8_t>((s.a + 1 + r.below(k_nodes - 1)) % k_nodes);
            s.delivery = r.below(3) == 0 ? LM_RECEIVED : LM_APPLIED;
            s.storage = r.below(3) == 0 ? LM_DURABLE : LM_VOLATILE;
        } else if (dice < 58) {
            s.kind = Kind::Run;
            s.value = static_cast<uint16_t>(200 + r.below(6000));
        } else if (dice < 68) {
            s.kind = Kind::Take;
            s.a = static_cast<uint8_t>(r.below(k_nodes));
        } else if (dice < 80) {
            s.kind = Kind::Apply;
            s.a = static_cast<uint8_t>(r.below(k_nodes));
        } else if (dice < 88) {
            s.kind = Kind::Loss;
            s.a = static_cast<uint8_t>(r.below(k_nodes - 1));
            static const uint16_t k_loss[] = {0, 100, 300, 600};
            s.value = k_loss[r.below(4)];
        } else if (dice < 93) {
            s.kind = Kind::LinkDown;
            s.a = static_cast<uint8_t>(r.below(k_nodes - 1));
        } else if (dice < 96) {
            s.kind = Kind::LinkUp;
            s.a = static_cast<uint8_t>(r.below(k_nodes - 1));
        } else {
            s.kind = Kind::Reboot;
            s.a = static_cast<uint8_t>(r.below(k_nodes));
        }
        steps.push_back(s);
    }
    return steps;
}

struct Result {
    std::string fail; // empty = every invariant held
    std::string log;
};

// One run of a schedule on a fresh network. Deterministic in (seed, steps).
class Run {
  public:
    Run(uint64_t seed, const std::vector<Step> &steps) : net_(seed), world_(WorldOptions{seed, 0}), steps_(steps) {}

    Result go() {
        setup();
        for (std::size_t i = 0; i < steps_.size() && fail_.empty(); ++i) {
            log("step %zu: %s", i, describe(steps_[i]).c_str());
            apply(steps_[i]);
            observe();
        }
        if (fail_.empty()) {
            quiesce();
        }
        return Result{fail_, log_};
    }

  private:
    struct Tracked {
        unsigned origin = 0;
        unsigned dest = 0;
        uint16_t tag = 0;
        uint8_t delivery = 0;
        uint8_t storage = 0;
        lm_operation_id_t op = 0;
        uint32_t evidence = 0;
        uint32_t outcome = 0;
        bool dead = false; // the origin restarted: its operation numbers are gone
        unsigned dest_boots = 0;
    };
    struct Held {
        lm_event_t ev{};
    };

    SimNode &node(unsigned i) { return world_.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    const DeviceId &id(unsigned i) { return kits_[i].kit.id; }
    void run_ms(uint64_t ms) { world_.run_until(world_.now_us() + ms * 1000); }
    uint64_t root_ms() { return k_root_ms0 + (world_.now_us() - t0_us_) / 1000; }

    __attribute__((format(printf, 2, 3))) void log(const char *fmt, ...) {
        char buf[240];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(buf, sizeof buf, fmt, ap);
        va_end(ap);
        log_ += "[" + std::to_string(world_.now_us() / 1000) + " ms] " + buf + "\n";
    }
    __attribute__((format(printf, 3, 4))) void violate(const char *name, const char *fmt, ...) {
        if (!fail_.empty()) {
            return;
        }
        char buf[300];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(buf, sizeof buf, fmt, ap);
        va_end(ap);
        fail_ = std::string(name) + ": " + buf;
        log("VIOLATION %s", fail_.c_str());
    }

    void boot(unsigned i) {
        if (node(i).boot() != Status::Ok || lm_start(ctx(i)) != LM_STATUS_OK) {
            violate("setup", "node %u did not boot", i);
        }
    }
    void set_time(unsigned i) {
        RootTimeBound b;
        b.term = RootTerm{1};
        b.earliest_ms = b.latest_ms = root_ms();
        b.valid = true;
        eng(i).set_root_time(b, node(i).clock.now());
        node(i).notify();
    }
    delivery::PathSpec spec(unsigned a, unsigned b, uint32_t rev) {
        delivery::PathSpec ps;
        ps.origin = ShortAddr{static_cast<uint16_t>(a + 1)};
        ps.dest = ShortAddr{static_cast<uint16_t>(b + 1)};
        const int dir = b > a ? 1 : -1;
        ps.len = static_cast<uint8_t>(b > a ? b - a : a - b);
        for (unsigned k = 0; k < ps.len; ++k) {
            ps.path[k] = static_cast<uint16_t>(static_cast<int>(a) + dir * static_cast<int>(k + 1) + 1);
        }
        ps.term = RootTerm{1};
        ps.revision = PathRevision{rev};
        return ps;
    }
    void routes(unsigned a, unsigned b) {
        ++rev_;
        (void)eng(a).delivery().install_route(id(b), spec(a, b, rev_), MonoTime::never());
        (void)eng(b).delivery().install_route(id(a), spec(b, a, rev_), MonoTime::never());
        node(a).notify();
        node(b).notify();
    }
    void connect(unsigned i, unsigned j) {
        (void)eng(i).link().connect(node(j).radio.mac(), node(i).clock.now(), true);
        node(i).notify();
        run_ms(2500);
    }

    void setup() {
        for (unsigned i = 0; i < k_nodes; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            (void)world_.add_node(o);
            kits_.push_back(i == 0 ? net_.make_root() : net_.make_node(i, static_cast<uint16_t>(i + 1)));
        }
        world_.make_chain();
        for (unsigned i = 0; i < k_nodes; ++i) {
            if (fleet::provision(node(i).store, net_, kits_[i]) != Status::Ok) {
                violate("setup", "provision %u", i);
                return;
            }
        }
        for (unsigned i = 0; i < k_nodes; ++i) {
            boot(i);
        }
        run_ms(50);
        t0_us_ = world_.now_us();
        for (unsigned i = 1; i < k_nodes; ++i) {
            connect(i, i - 1);
        }
        for (unsigned i = 0; i < k_nodes; ++i) {
            set_time(i);
        }
        for (unsigned a = 0; a < k_nodes; ++a) {
            for (unsigned b = a + 1; b < k_nodes; ++b) {
                routes(a, b);
            }
        }
        held_.resize(k_nodes);
        boots_.assign(k_nodes, 0);
    }

    void link_state(unsigned l, bool up, uint16_t loss) {
        LinkParams p;
        p.up = up;
        p.loss_permille = loss;
        world_.set_link(static_cast<uint16_t>(l), static_cast<uint16_t>(l + 1), p);
        link_up_[l] = up;
        link_loss_[l] = loss;
    }

    void take(unsigned i) {
        for (;;) {
            lm_event_t e{};
            e.struct_size = sizeof(e);
            e.abi_version = LM_ABI_VERSION;
            std::array<uint8_t, 600> buf{};
            size_t req = 0;
            if (lm_next_event(ctx(i), &e, buf.data(), buf.size(), &req) != LM_STATUS_OK) {
                return;
            }
            if (e.kind != LM_EVENT_MESSAGE || req < 2) {
                continue;
            }
            const uint16_t tag = static_cast<uint16_t>((buf[0] << 8) | buf[1]);
            seen_[tag].push_back(i);
            log("node %u app got message %u (event reason %u)", i, tag, e.reason);
            Held h;
            h.ev = e;
            held_[i].push_back({h, tag});
        }
    }
    void apply_results(unsigned i) {
        take(i);
        for (auto &h : held_[i]) {
            lm_message_ref_t ref{};
            ref.origin = h.first.ev.peer;
            ref.assignment_generation = h.first.ev.origin_assignment_generation;
            ref.id = h.first.ev.message_id;
            std::memcpy(ref.intent_hash, h.first.ev.intent_hash, 32);
            if (lm_report_application_result(ctx(i), &ref, LM_OUTCOME_APPLIED, nullptr, 0, nullptr) == LM_STATUS_OK) {
                reported_[h.second] = true;
                log("node %u app reported APPLIED for %u", i, h.second);
            }
            node(i).notify();
        }
        held_[i].clear();
    }

    void reboot(unsigned i) {
        for (Tracked &t : tracked_) {
            t.dead = t.dead || t.origin == i;
            if (t.dest == i) {
                ++t.dest_boots;
            }
        }
        held_[i].clear();
        ++boots_[i];
        node(i).power_cut();
        node(i).store.power_restore();
        boot(i);
        run_ms(31'000); // the per-peer handshake gate (docs/06 §8)
        for (const int d : {-1, 1}) {
            const int j = static_cast<int>(i) + d;
            if (j >= 0 && j < static_cast<int>(k_nodes)) {
                connect(i, static_cast<unsigned>(j));
            }
        }
        set_time(i);
        for (unsigned j = 0; j < k_nodes; ++j) {
            if (j != i) {
                routes(i, j);
            }
        }
    }

    void apply(const Step &s) {
        switch (s.kind) {
        case Kind::Send: send(s); break;
        case Kind::Run: run_ms(s.value); break;
        case Kind::Take: take(s.a); break;
        case Kind::Apply: apply_results(s.a); break;
        case Kind::Loss: link_state(s.a, link_up_[s.a], s.value); break;
        case Kind::LinkDown: link_state(s.a, false, link_loss_[s.a]); break;
        case Kind::LinkUp: link_state(s.a, true, link_loss_[s.a]); break;
        case Kind::Reboot: reboot(s.a); break;
        }
    }

    void send(const Step &s) {
        Tracked t;
        t.origin = s.a;
        t.dest = s.b;
        t.tag = ++next_tag_;
        t.delivery = s.delivery;
        t.storage = s.storage;
        t.dest_boots = 0;
        Bytes payload(20, 0x5A);
        payload[0] = static_cast<uint8_t>(t.tag >> 8);
        payload[1] = static_cast<uint8_t>(t.tag);
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_NODE;
        std::memcpy(rq.destination.node.bytes, id(s.b).bytes.data(), 32);
        rq.app_port = 100;
        rq.delivery = s.delivery;
        rq.storage = s.storage;
        rq.priority = LM_PRIORITY_NORMAL;
        rq.queue_mode = LM_FIFO;
        rq.root_term = 1;
        rq.expires_root_ms = root_ms() + k_ttl_ms;
        deadline_ms_[t.tag] = rq.expires_root_ms;
        const lm_status_t st = lm_send(ctx(s.a), &rq, payload.data(), payload.size(), &t.op);
        node(s.a).notify();
        if (st != LM_STATUS_OK) {
            log("send refused locally: status %d (no operation exists)", static_cast<int>(st));
            return;
        }
        log("message %u accepted as operation %llu", t.tag, static_cast<unsigned long long>(t.op));
        tracked_.push_back(t);
    }

    static unsigned rank(uint32_t outcome) {
        switch (outcome) {
        case LM_OUTCOME_PENDING: return 0;
        case LM_OUTCOME_EXPIRED:
        case LM_OUTCOME_INDETERMINATE: return 1;
        case LM_OUTCOME_RECEIVED: return 2;
        case LM_OUTCOME_APPLIED:
        case LM_OUTCOME_REJECTED: return 3;
        default: return 1; // cancelled / superseded / submitted: not produced by these schedules
        }
    }

    void observe() {
        for (Tracked &t : tracked_) {
            if (t.dead) {
                continue;
            }
            lm_operation_t o{};
            o.struct_size = sizeof(o);
            o.abi_version = LM_ABI_VERSION;
            if (lm_get_operation(ctx(t.origin), t.op, &o) != LM_STATUS_OK) {
                t.dead = true;
                continue;
            }
            if ((o.evidence_bits & t.evidence) != t.evidence) {
                violate("evidence-monotone", "message %u lost evidence bits %#x -> %#x", t.tag, t.evidence, o.evidence_bits);
            }
            if (rank(o.outcome) < rank(t.outcome) ||
                (rank(t.outcome) == 3 && o.outcome != t.outcome)) {
                violate("outcome-monotone", "message %u outcome %u -> %u", t.tag, t.outcome, o.outcome);
            }
            if ((o.outcome == LM_OUTCOME_APPLIED || (o.evidence_bits & ev::app_applied) != 0) && !reported_[t.tag]) {
                violate("no-applied-without-destination", "message %u shows APPLIED (outcome %u, evidence %#x) but the destination "
                                                          "application never reported it",
                        t.tag, o.outcome, o.evidence_bits);
            }
            if (o.outcome == LM_OUTCOME_REJECTED && (o.evidence_bits & ev::app_rejected) == 0 && (o.evidence_bits & ev::refused) == 0) {
                violate("no-rejected-without-destination", "message %u REJECTED with evidence %#x", t.tag, o.evidence_bits);
            }
            t.evidence = o.evidence_bits;
            t.outcome = o.outcome;
        }
        for (const auto &kv : seen_) {
            unsigned boots = 0;
            for (const Tracked &t : tracked_) {
                if (t.tag == kv.first) {
                    boots = boots_[t.dest];
                }
            }
            if (kv.second.size() > 1u + boots) {
                violate("no-duplicate-application", "message %u reached the destination application %zu times (destination restarted %u times)",
                        kv.first, kv.second.size(), boots);
            }
        }
    }

    void quiesce() {
        log("-- healing: every link up and clean, applications answer --");
        for (unsigned l = 0; l + 1 < k_nodes; ++l) {
            link_state(l, true, 0);
        }
        for (int round = 0; round < 6; ++round) {
            run_ms(40'000);
            for (unsigned i = 0; i < k_nodes; ++i) {
                apply_results(i);
            }
            observe();
        }
        run_ms(40'000);
        for (unsigned i = 0; i < k_nodes; ++i) {
            take(i);
        }
        observe();
        for (const Tracked &t : tracked_) {
            if (t.dead) {
                continue;
            }
            if (t.outcome == LM_OUTCOME_PENDING) {
                violate("no-operation-open-forever", "message %u (%u->%u, delivery %u, storage %u) is still PENDING %llu ms after its "
                                                     "deadline",
                        t.tag, t.origin, t.dest, t.delivery, t.storage,
                        static_cast<unsigned long long>(root_ms() - deadline_ms_[t.tag]));
            }
            const bool stored = (t.evidence & ev::end_received) != 0 || t.outcome == LM_OUTCOME_RECEIVED ||
                                t.outcome == LM_OUTCOME_APPLIED;
            if (stored && seen_[t.tag].empty() && !(t.storage == LM_VOLATILE && boots_[t.dest] != 0)) {
                violate("received-means-stored", "message %u has receipt evidence %#x but the destination application never got it",
                        t.tag, t.evidence);
            }
        }
    }

    fleet::Network net_;
    World world_;
    const std::vector<Step> &steps_;
    std::vector<fleet::NodeKit> kits_;
    std::vector<Tracked> tracked_;
    std::vector<std::vector<std::pair<Held, uint16_t>>> held_;
    std::map<uint16_t, std::vector<unsigned>> seen_;
    std::map<uint16_t, bool> reported_;
    std::map<uint16_t, uint64_t> deadline_ms_;
    std::vector<unsigned> boots_;
    std::array<bool, k_nodes> link_up_{true, true, true, true};
    std::array<uint16_t, k_nodes> link_loss_{};
    uint64_t t0_us_ = 0;
    uint32_t rev_ = 0;
    uint16_t next_tag_ = 0;
    std::string fail_;
    std::string log_;
};

std::string name_of(const std::string &fail) { return fail.substr(0, fail.find(':')); }

// Greedy minimisation: drop steps while the same invariant still fails.
std::vector<Step> minimise(uint64_t seed, std::vector<Step> steps, const std::string &invariant) {
    unsigned budget = 150;
    for (bool changed = true; changed && budget != 0;) {
        changed = false;
        for (std::size_t i = steps.size(); i-- > 0 && budget != 0;) {
            std::vector<Step> cand = steps;
            cand.erase(cand.begin() + static_cast<long>(i));
            --budget;
            const Result r = Run(seed, cand).go();
            if (!r.fail.empty() && name_of(r.fail) == invariant) {
                steps = cand;
                changed = true;
            }
        }
    }
    return steps;
}

unsigned env_or(const char *name, unsigned dflt) {
    const char *v = std::getenv(name);
    return v != nullptr ? static_cast<unsigned>(std::strtoul(v, nullptr, 10)) : dflt;
}

} // namespace

LM_TEST("D01 D02 D04 D10 MODEL sim: seeded random message / loss / link / reboot schedules keep the evidence invariants") {
    const unsigned only = env_or("LM_MODEL_SEED", 0);
    const unsigned seeds = only != 0 ? 1 : env_or("LM_MODEL_SEEDS", 48);
    unsigned failures = 0;
    unsigned sends = 0;
    unsigned reboots = 0;
    for (unsigned k = 0; k < seeds; ++k) {
        const uint64_t seed = only != 0 ? only : 1000 + k;
        const std::vector<Step> steps = generate(seed, 28);
        for (const Step &s : steps) {
            sends += s.kind == Kind::Send ? 1 : 0;
            reboots += s.kind == Kind::Reboot ? 1 : 0;
        }
        const Result r = Run(seed, steps).go();
        if (std::getenv("LM_MODEL_LOG") != nullptr) {
            std::printf("--- seed %llu ---\n%s", static_cast<unsigned long long>(seed), r.log.c_str());
        }
        if (r.fail.empty()) {
            continue;
        }
        ++failures;
        std::fprintf(stderr, "MODEL FAILURE seed %llu (LM_MODEL_SEED=%llu) commit %s\n  %s\n--- event log ---\n%s",
                     static_cast<unsigned long long>(seed), static_cast<unsigned long long>(seed), LM_MODEL_COMMIT, r.fail.c_str(),
                     r.log.c_str());
        const std::vector<Step> small = minimise(seed, steps, name_of(r.fail));
        std::fprintf(stderr, "--- minimal counterexample (%zu of %zu steps, same invariant) ---\n", small.size(), steps.size());
        for (const Step &s : small) {
            std::fprintf(stderr, "  %s\n", describe(s).c_str());
        }
        LM_CHECK(false);
    }
    std::printf("  [measure] MODEL: %u seeds, %u sends, %u restarts, %u invariant failures (commit %s)\n", seeds, sends, reboots,
                failures, LM_MODEL_COMMIT);
}

LM_TEST_MAIN()
