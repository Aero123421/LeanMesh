// Cross-language provisioning test driver. Only reads ephemeral pytest fixtures; never shipped.
// The issuer is Python/cryptography; verification and Join are the unchanged SDK/PSA/EDHOC path.
#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "capi/context.hpp"
#include "core/member/credentials.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_provision.hpp"
#include "port/sim/sim_world.hpp"
#include "security/crypto.hpp"
#include "store/record.hpp"

using namespace lm;
using Bytes = std::vector<uint8_t>;

namespace {

ByteView view(const Bytes &v) { return ByteView{v.data(), v.size()}; }

bool read(const std::string &dir, const char *name, Bytes &out) {
    std::ifstream f(dir + "/" + name, std::ios::binary);
    if (!f) return false;
    out.resize(1025);
    f.read(reinterpret_cast<char *>(out.data()), static_cast<std::streamsize>(out.size()));
    const auto n = f.gcount();
    if (n > 1024 || f.bad()) return false;
    out.resize(static_cast<std::size_t>(n));
    return !out.empty();
}

struct Input {
    member::TrustAnchor trust;
    member::DeviceCredential root_dc, leaf_dc;
    member::RootDelegation delegation;
    member::AssignmentTicket ticket;
    Bytes root, leaf, delegation_cose, ticket_cose, expected;
};

// A transfer (docs/07 §8): the second domain B with its own root, and the fleet's ticket A -> B.
struct Move {
    member::DeviceCredential root_dc;
    member::RootDelegation delegation;
    member::AssignmentTicket ticket;
    Bytes root, delegation_cose, ticket_cose, expected, stale, foreign;
    bool nonce_mode = false;
};

Status verify(const std::string &dir, Input &in) {
    Bytes public_key, fleet;
    if (!read(dir, "fleet.pub", public_key) || public_key.size() != 65 || public_key[0] != 4 ||
        !read(dir, "fleet.id", fleet) || fleet.size() != 16 ||
        !read(dir, "root.cose", in.root) || !read(dir, "leaf.cose", in.leaf) ||
        !read(dir, "delegation.cose", in.delegation_cose) ||
        !read(dir, "ticket.cose", in.ticket_cose) || !read(dir, "expected.cose", in.expected)) {
        return Status::InvalidArgument;
    }
    sec::PublicKey key;
    std::copy_n(public_key.begin() + 1, 32, key.x.begin());
    std::copy_n(public_key.begin() + 33, 32, key.y.begin());
    FleetId fid;
    std::copy_n(fleet.begin(), 16, fid.bytes.begin());
    LM_TRY(member::make_trust_anchor(fid, key, 0, in.trust));
    LM_TRY(member::check_device_credential(in.trust, view(in.root), in.root_dc));
    LM_TRY(member::check_device_credential(in.trust, view(in.leaf), in.leaf_dc));
    LM_TRY(member::check_root_delegation(in.trust, view(in.delegation_cose), in.delegation));
    LM_TRY(member::check_assignment_ticket(in.trust, view(in.ticket_cose), in.leaf_dc, view(in.leaf),
                                         view(in.delegation_cose), in.ticket));
    member::ExpectedSet expected;
    LM_TRY(member::check_expected_set(in.trust, &in.delegation, view(in.expected), expected));
    member::Envelope env;
    ByteView data;
    LM_TRY(member::peek_signed(view(in.expected), member::k_type_expected_set, env, data));
    if (in.delegation.root != in.root_dc.device || in.ticket.target != in.delegation.domain ||
        !in.ticket.source.is_zero() || in.ticket.expected_old != 0 || in.ticket.mode != 1 ||
        env.domain != in.delegation.domain || expected.page >= expected.pages) {
        return Status::AuthRejected;
    }
    Sha256Digest hash{};
    LM_TRY(sec::sha256(view(in.ticket_cose), hash));
    for (std::size_t i = 0; i < expected.count; ++i) {
        const auto &e = expected.entries[i];
        if (e.device == in.leaf_dc.device && e.assignment == in.ticket.new_generation &&
            e.grant_hash == hash && e.allowed) return Status::Ok;
    }
    return Status::AuthRejected;
}

Status commit(port::Store &store, uint16_t id, ByteView payload) {
    auto job = std::make_unique<store::RecordJob>();
    if (payload.size() > job->payload.size()) return Status::NoCapacity;
    job->op = store::RecordJob::Op::Commit;
    job->id = id;
    job->payload_len = static_cast<uint32_t>(payload.size());
    std::copy(payload.begin(), payload.end(), job->payload.begin());
    return store::record_commit(store, *job);
}


// Fixture-only root membership. No fleet test issuer or deterministic key is linked here.
Status root_member(const Bytes &root_cose, const Bytes &scalar, const member::DeviceCredential &dc,
                   const DomainId &domain, Bytes &out) {
    member::MemberCredential mc;
    mc.device = dc.device;
    mc.address = ShortAddr{1};
    mc.assignment = AssignmentGen{1};
    mc.membership = MembershipGen{1};
    mc.role = 2;
    mc.relay_allowed = true;
    mc.lease_expires_root_ms = UINT64_MAX;
    LM_TRY(sec::sha256(view(root_cose), mc.credential_hash));
    std::array<uint8_t, 1024> buf{};
    std::size_t n = 0;
    LM_TRY(member::encode_member_credential(mc, MutByteView{buf}, n));
    member::Envelope env;
    env.type = member::k_type_member_credential;
    env.domain = domain;
    env.issuer = dc.device;
    env.revision = 1;
    env.request.bytes[0] = 1;
    sec::KeyHandle key;
    LM_TRY(sec::import_signing_key(view(scalar), key));
    out.assign(1024, 0);
    const Status issued =
        member::issue_signed(key, env, ByteView{buf.data(), n}, MutByteView{out.data(), out.size()}, n);
    sec::destroy_key(key);
    LM_TRY(issued);
    out.resize(n);
    return Status::Ok;
}

Status provision_root(sim::SimNode &node, const Bytes &scalar, const Bytes &root_cose, const Bytes &delegation_cose,
                      const member::TrustAnchor &trust, const member::DeviceCredential &dc,
                      const member::RootDelegation &delegation) {
    Bytes member_cose;
    LM_TRY(root_member(root_cose, scalar, dc, delegation.domain, member_cose));
    sim::ProvisionInput provision;
    provision.scalar32 = view(scalar);
    provision.device_cose = view(root_cose);
    provision.trust = trust;
    provision.delegation_cose = view(delegation_cose);
    provision.member_cose = view(member_cose);
    provision.new_ledger_domain = &delegation.domain;
    return sim::provision_store(node.store, provision);
}

struct Rig {
    sim::World world{sim::WorldOptions{831, 0}};
    void run(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    lm_context_t *ctx(uint16_t i) { return world.node(i).ctx(); }
    root::Ledger &ledger(uint16_t i) { return ctx(i)->engine.ledger(); }
    // The root clock of node 0 on every powered node of term 1 (the roots of this rig booted together).
    void set_time() {
        for (uint16_t i = 0; i < 3; ++i) {
            auto &node = world.node(i);
            if (node.powered() && (!ctx(i)->engine.identity().is_member() ||
                                   ctx(i)->engine.identity().member().root_term == RootTerm{1})) {
                RootTimeBound t;
                t.term = RootTerm{1};
                t.earliest_ms = t.latest_ms = world.node(1).clock.now().to_ms();
                t.valid = true;
                ctx(i)->engine.set_root_time(t, node.clock.now());
            }
        }
    }
    // lm_install_control and its operation: Ok, or the call's/operation's refusal status.
    Status install(uint16_t node, uint32_t type, const Bytes &obj) {
        lm_operation_id_t operation = 0;
        lm_status_t installed = LM_STATUS_BUSY;
        for (unsigned i = 0; i < 200 && installed == LM_STATUS_BUSY; ++i) {
            installed = lm_install_control(ctx(node), type, obj.data(), obj.size(), &operation);
            if (installed == LM_STATUS_BUSY) run(5);
        }
        if (installed != LM_STATUS_OK) return static_cast<Status>(installed);
        for (unsigned i = 0; i < 400; ++i) {
            run(5);
            lm_event_t event{};
            event.struct_size = sizeof(event);
            event.abi_version = LM_ABI_VERSION;
            while (lm_next_event(ctx(node), &event, nullptr, 0, nullptr) == LM_STATUS_OK) {
                if (event.kind == LM_EVENT_OPERATION && event.operation_id == operation) {
                    return event.reason == 0 ? Status::Ok : static_cast<Status>(event.reason);
                }
            }
        }
        return Status::Expired;
    }
    Status join(uint16_t node, uint8_t request_byte, uint32_t mode) {
        lm_join_request_t request{};
        request.struct_size = sizeof(request);
        request.abi_version = LM_ABI_VERSION;
        request.request_id.bytes[0] = request_byte;
        request.mode = mode;
        lm_operation_id_t operation = 0;
        lm_status_t accepted = LM_STATUS_AUTH_PENDING;
        for (unsigned i = 0; i < 200 && (accepted == LM_STATUS_AUTH_PENDING || accepted == LM_STATUS_BUSY); ++i) {
            accepted = lm_join(ctx(node), &request, &operation);
            if (accepted == LM_STATUS_AUTH_PENDING || accepted == LM_STATUS_BUSY) run(5);
        }
        world.node(node).notify();
        return static_cast<Status>(accepted);
    }
    // The membership's join phase is Idle (a join ends after the root's confirmation: its mode-0 nonce is spent then).
    bool idle(uint16_t node) {
        for (unsigned i = 0; i < 6000; ++i) {
            if (ctx(node)->engine.membership().phase() == member::JoinPhase::Idle) return true;
            run(5);
        }
        return false;
    }
    bool in_domain(uint16_t node, const DomainId &domain, uint64_t assignment) {
        lm_membership_t m{};
        m.struct_size = sizeof(m);
        m.abi_version = LM_ABI_VERSION;
        return lm_membership_get(ctx(node), &m) == LM_STATUS_OK && m.state == LM_ACTIVE &&
               std::equal(domain.bytes.begin(), domain.bytes.end(), m.domain.bytes) &&
               m.assignment_generation == assignment;
    }
};

// Node 0: root A, node 1: root B (transfer only), last node: the leaf. Root A admits the leaf with the initial
// ticket (PREAPPROVED, the ExpectedSet page as issued) and the leaf is ACTIVE in A when this returns Ok.
Status join(const std::string &dir, const Input &in, const Move *move, Rig &rig) {
    Bytes root_scalar, leaf_scalar, rootb_scalar;
    if (!read(dir, "root.scalar", root_scalar) || root_scalar.size() != 32 ||
        !read(dir, "leaf.scalar", leaf_scalar) || leaf_scalar.size() != 32 ||
        (move != nullptr && (!read(dir, "rootb.scalar", rootb_scalar) || rootb_scalar.size() != 32))) {
        return Status::InvalidArgument;
    }
    sim::NodeOptions opts;
    opts.role = Role::Root;
    (void)rig.world.add_node(opts);
    if (move != nullptr) (void)rig.world.add_node(opts);
    opts.role = Role::Leaf;
    const uint16_t leaf = rig.world.add_node(opts);
    rig.world.make_full();
    LM_TRY(provision_root(rig.world.node(0), root_scalar, in.root, in.delegation_cose, in.trust, in.root_dc,
                          in.delegation));
    if (move != nullptr) {
        LM_TRY(provision_root(rig.world.node(1), rootb_scalar, move->root, move->delegation_cose, in.trust,
                              move->root_dc, move->delegation));
    }
    sim::ProvisionInput provision;
    provision.scalar32 = view(leaf_scalar);
    provision.device_cose = view(in.leaf);
    provision.trust = in.trust;
    LM_TRY(sim::provision_store(rig.world.node(leaf).store, provision));
    LM_TRY(commit(rig.world.node(leaf).store, store::rec::assignment_ticket, view(in.ticket_cose)));
    sec::secure_zero(MutByteView{root_scalar.data(), root_scalar.size()});
    sec::secure_zero(MutByteView{leaf_scalar.data(), leaf_scalar.size()});
    sec::secure_zero(MutByteView{rootb_scalar.data(), rootb_scalar.size()});
    for (uint16_t i = 0; i <= leaf; ++i) {
        LM_TRY(rig.world.node(i).boot());
        if (lm_start(rig.ctx(i)) != LM_STATUS_OK) return Status::RecoveryRequired;
    }
    for (uint16_t i = 0; i < leaf; ++i) {
        auto &ledger = rig.ledger(i);
        for (unsigned k = 0; k < 400 && !ledger.ready() && !ledger.failed(); ++k) rig.run(5);
        if (!ledger.ready() || ledger.failed()) return Status::RecoveryRequired;
    }
    rig.ledger(0).set_join_mode(root::JoinMode::Preapproved);
    LM_TRY(rig.install(0, 5, in.expected));
    LM_TRY(rig.join(leaf, 2, LM_JOIN_NEW));
    for (unsigned i = 0; i < 8000; ++i) {
        rig.run(5);
        const auto *entry = rig.ledger(0).find(in.leaf_dc.device);
        if (rig.ctx(leaf)->engine.identity().is_member() && entry != nullptr &&
            entry->state == root::EntryState::Active && entry->confirmed &&
            entry->assignment == in.ticket.new_generation) {
            return rig.idle(leaf) ? Status::Ok : Status::Expired; // the join is over, the device's nonce is spent
        }
    }
    return Status::Expired;
}

// B's root: nothing here depends on the device's nonce.
Status load_move(const std::string &dir, const Input &in, Move &mv) {
    if (!read(dir, "rootb.cose", mv.root) || !read(dir, "delegation-b.cose", mv.delegation_cose)) {
        return Status::InvalidArgument;
    }
    LM_TRY(member::check_device_credential(in.trust, view(mv.root), mv.root_dc));
    LM_TRY(member::check_root_delegation(in.trust, view(mv.delegation_cose), mv.delegation));
    return mv.delegation.root == mv.root_dc.device && mv.delegation.domain != in.delegation.domain
               ? Status::Ok
               : Status::AuthRejected;
}

// The ticket A -> B and the page that grants it at B, verified like the root and the device do, and the two
// tickets the device must refuse.
Status verify_move(const std::string &dir, const Input &in, Move &mv) {
    if (!read(dir, "transfer.cose", mv.ticket_cose) || !read(dir, "expected-b.cose", mv.expected) ||
        !read(dir, "stale.cose", mv.stale) || !read(dir, "foreign.cose", mv.foreign)) {
        return Status::InvalidArgument;
    }
    LM_TRY(member::check_assignment_ticket(in.trust, view(mv.ticket_cose), in.leaf_dc, view(in.leaf),
                                           view(mv.delegation_cose), mv.ticket));
    member::ExpectedSet expected;
    LM_TRY(member::check_expected_set(in.trust, &mv.delegation, view(mv.expected), expected));
    Sha256Digest hash{};
    LM_TRY(sec::sha256(view(mv.ticket_cose), hash));
    bool granted = false;
    for (std::size_t i = 0; i < expected.count; ++i) {
        const auto &e = expected.entries[i];
        granted = granted || (e.device == in.leaf_dc.device && e.assignment == mv.ticket.new_generation &&
                              e.grant_hash == hash && e.allowed);
    }
    // The transfer leaves A (from its current assignment) for B, named by B's delegation, mode as asked.
    if (!granted || mv.ticket.source != in.delegation.domain || mv.ticket.target != mv.delegation.domain ||
        mv.ticket.expected_old != in.ticket.new_generation || mv.ticket.mode != (mv.nonce_mode ? 0 : 1) ||
        mv.ticket.new_generation <= mv.ticket.expected_old) {
        return Status::AuthRejected;
    }
    return Status::Ok;
}

// LM_TRY that also says which expression failed (the caller sees only a status name).
#define TRY_SAY(expr)                                                                              \
    do {                                                                                           \
        const Status say_status_ = (expr);                                                         \
        if (say_status_ != Status::Ok) {                                                           \
            std::fprintf(stderr, "transfer step failed: %s -> %s\n", #expr, status_name(say_status_)); \
            return say_status_;                                                                    \
        }                                                                                          \
    } while (0)

void note(const char *what) { std::fprintf(stderr, "transfer: %s\n", what); }

// A step failed: say which.
Status fail(const char *step) {
    std::fprintf(stderr, "transfer step failed: %s\n", step);
    return Status::Conflict;
}

// A -> B with the Python-issued ticket while root A is powered off; then A reconciles from the same ticket.
Status transfer(const std::string &dir, const Input &in, bool nonce_mode) {
    Move mv;
    mv.nonce_mode = nonce_mode;
    TRY_SAY(load_move(dir, in, mv));
    if (!nonce_mode) TRY_SAY(verify_move(dir, in, mv)); // nothing waits for the device: refuse before the run
    Rig rig;
    TRY_SAY(join(dir, in, &mv, rig)); // the leaf is ACTIVE in A
    note("ACTIVE in A");
    const uint16_t leaf = 2;
    const DeviceId self = in.leaf_dc.device;
    if (nonce_mode) { // the issuer needs the device's nonce: print it, wait for the files issued for it
        std::array<uint8_t, 16> nonce{};
        TRY_SAY(static_cast<Status>(lm_transfer_nonce_get(rig.ctx(leaf), nonce.data())));
        static const char hex[] = "0123456789abcdef";
        std::string line = "NONCE ";
        for (uint8_t b : nonce) {
            line += hex[b >> 4];
            line += hex[b & 15];
        }
        std::cout << line << std::endl;
        std::string go;
        if (!std::getline(std::cin, go) || go != "GO") return Status::InvalidArgument;
    }
    if (nonce_mode) TRY_SAY(verify_move(dir, in, mv));
    // Root A is gone: the move needs only the fleet's ticket and root B (docs/07 §8).
    rig.world.node(0).power_cut();
    rig.world.node(0).store.power_restore();
    rig.ledger(1).set_join_mode(root::JoinMode::Preapproved);
    TRY_SAY(rig.install(1, 5, mv.expected));
    note("root A off, root B holds the ExpectedSet page");
    // Refused at the device: wrong current assignment (stale), another nonce (mode 0) or another source domain
    // (foreign), an initial ticket.
    if (rig.install(leaf, 3, mv.stale) == Status::Ok) return fail("stale ticket installed");
    if (rig.install(leaf, 3, mv.foreign) == Status::Ok) return fail("foreign ticket installed");
    if (rig.install(leaf, 3, in.ticket_cose) == Status::Ok) return fail("initial ticket installed by a member");
    note("stale, foreign and initial tickets refused at the device");
    TRY_SAY(rig.install(leaf, 3, mv.ticket_cose));
    TRY_SAY(rig.join(leaf, 3, LM_JOIN_TRANSFER_CANDIDATE));
    bool moved = false;
    bool both = false;
    for (unsigned i = 0; i < 12000 && !moved; ++i) {
        rig.run(5);
        const bool in_a = rig.in_domain(leaf, in.delegation.domain, in.ticket.new_generation);
        moved = rig.in_domain(leaf, mv.delegation.domain, mv.ticket.new_generation);
        both = both || (in_a && moved);
    }
    if (!moved || both || !rig.idle(leaf)) return fail("the device did not move to B");
    note("ACTIVE in B (generation as ticketed), never in A and B at once");
    const auto *entry = rig.ledger(1).find(self);
    if (entry == nullptr || entry->state != root::EntryState::Active || entry->assignment != mv.ticket.new_generation) {
        return fail("B does not list the device ACTIVE with the new generation");
    }
    if (rig.ctx(leaf)->engine.identity().self() != self) return fail("DeviceId changed");
    // The ticket is spent: installed again it is not a transfer away from the device's current assignment.
    if (rig.install(leaf, 3, mv.ticket_cose) == Status::Ok) return fail("replayed ticket installed");
    // A returns: its ledger has not heard of the move; the same fleet ticket reconciles it, then A refuses the device.
    TRY_SAY(rig.world.node(0).boot());
    if (lm_start(rig.ctx(0)) != LM_STATUS_OK) return Status::RecoveryRequired;
    rig.run(200);
    rig.set_time();
    entry = rig.ledger(0).find(self);
    if (entry == nullptr || entry->state != root::EntryState::Active) return fail("A forgot the device early");
    TRY_SAY(rig.install(0, 3, mv.ticket_cose));
    entry = rig.ledger(0).find(self);
    if (entry == nullptr || entry->state != root::EntryState::Left) return fail("A was not reconciled");
    note("root A back: ACTIVE entry reconciled to LEFT by the same ticket");
    Status connecting = Status::Busy;
    for (unsigned i = 0; i < 400 && connecting == Status::Busy; ++i) {
        connecting = rig.ctx(0)->engine.link().connect(rig.world.node(leaf).radio.mac(), rig.world.node(0).clock.now());
        if (connecting == Status::Busy) rig.run(50);
    }
    TRY_SAY(connecting);
    rig.world.node(0).notify();
    rig.run(6000);
    if (rig.ctx(0)->engine.link().neighbors().find_device(self) != nullptr) {
        return fail("A has a session with the device");
    }
    note("root A has no session with the device");
    return rig.in_domain(leaf, mv.delegation.domain, mv.ticket.new_generation) ? Status::Ok : fail("B membership lost");
}

} // namespace

int main(int argc, char **argv) {
    const std::string mode = argc >= 2 ? argv[1] : "";
    const bool transfer_mode = mode == "transfer" || mode == "transfer-nonce";
    if (argc != 3 || (mode != "verify" && mode != "join" && !transfer_mode)) return 2;
    Input in;
    Status status = sec::crypto_init();
    if (status == Status::Ok) status = verify(argv[2], in);
    if (status == Status::Ok && mode == "join") {
        Rig rig;
        status = join(argv[2], in, nullptr, rig);
    }
    if (status == Status::Ok && transfer_mode) status = transfer(argv[2], in, mode == "transfer-nonce");
    std::cout << status_name(status) << '\n';
    return status == Status::Ok ? 0 : 1;
}
