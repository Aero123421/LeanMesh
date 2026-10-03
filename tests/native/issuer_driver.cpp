// Cross-language provisioning test driver. Only reads ephemeral pytest fixtures; never shipped.
// The issuer is Python/cryptography; verification and Join are the unchanged SDK/PSA/EDHOC path.
#include <algorithm>
#include <array>
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

Status join(const std::string &dir, const Input &in) {
    Bytes root_scalar, leaf_scalar;
    if (!read(dir, "root.scalar", root_scalar) || root_scalar.size() != 32 ||
        !read(dir, "leaf.scalar", leaf_scalar) || leaf_scalar.size() != 32) return Status::InvalidArgument;
    // Fixture-only root membership. No fleet test issuer or deterministic key is linked here.
    member::MemberCredential mc;
    mc.device = in.root_dc.device;
    mc.address = ShortAddr{1};
    mc.assignment = AssignmentGen{1};
    mc.membership = MembershipGen{1};
    mc.role = 2;
    mc.relay_allowed = true;
    mc.lease_expires_root_ms = UINT64_MAX;
    LM_TRY(sec::sha256(view(in.root), mc.credential_hash));
    std::array<uint8_t, 1024> buf{};
    std::size_t n = 0;
    LM_TRY(member::encode_member_credential(mc, MutByteView{buf}, n));
    member::Envelope env;
    env.type = member::k_type_member_credential;
    env.domain = in.delegation.domain;
    env.issuer = in.root_dc.device;
    env.revision = 1;
    env.request.bytes[0] = 1;
    sec::KeyHandle key;
    LM_TRY(sec::import_signing_key(view(root_scalar), key));
    Bytes root_member(1024);
    const Status issued = member::issue_signed(key, env, ByteView{buf.data(), n},
                                               MutByteView{root_member.data(), root_member.size()}, n);
    sec::destroy_key(key);
    LM_TRY(issued);
    root_member.resize(n);
    sim::World world(sim::WorldOptions{831, 0});
    sim::NodeOptions opts;
    opts.role = Role::Root;
    (void)world.add_node(opts);
    opts.role = Role::Leaf;
    (void)world.add_node(opts);
    world.make_full();
    sim::ProvisionInput provision;
    provision.scalar32 = view(root_scalar);
    provision.device_cose = view(in.root);
    provision.trust = in.trust;
    provision.delegation_cose = view(in.delegation_cose);
    provision.member_cose = view(root_member);
    provision.new_ledger_domain = &in.delegation.domain;
    LM_TRY(sim::provision_store(world.node(0).store, provision));
    provision = sim::ProvisionInput{};
    provision.scalar32 = view(leaf_scalar);
    provision.device_cose = view(in.leaf);
    provision.trust = in.trust;
    LM_TRY(sim::provision_store(world.node(1).store, provision));
    LM_TRY(commit(world.node(1).store, store::rec::assignment_ticket, view(in.ticket_cose)));
    sec::secure_zero(MutByteView{root_scalar.data(), root_scalar.size()});
    sec::secure_zero(MutByteView{leaf_scalar.data(), leaf_scalar.size()});
    for (uint16_t i = 0; i < 2; ++i) {
        LM_TRY(world.node(i).boot());
        if (lm_start(world.node(i).ctx()) != LM_STATUS_OK) return Status::RecoveryRequired;
    }
    auto run = [&](uint64_t ms) { world.run_until(world.now_us() + ms * 1000); };
    auto &ledger = world.node(0).ctx()->engine.ledger();
    for (unsigned i = 0; i < 400 && !ledger.ready() && !ledger.failed(); ++i) run(5);
    if (!ledger.ready() || ledger.failed()) return Status::RecoveryRequired;
    ledger.set_join_mode(root::JoinMode::Preapproved);
    lm_operation_id_t operation = 0;
    lm_status_t installed = LM_STATUS_BUSY;
    for (unsigned i = 0; i < 200 && installed == LM_STATUS_BUSY; ++i) {
        installed = lm_install_control(world.node(0).ctx(), 5, in.expected.data(), in.expected.size(), &operation);
        if (installed == LM_STATUS_BUSY) run(5);
    }
    if (installed != LM_STATUS_OK) return static_cast<Status>(installed);
    bool applied = false;
    for (unsigned i = 0; i < 400 && !applied; ++i) {
        run(5);
        lm_event_t event{};
        event.struct_size = sizeof(event);
        event.abi_version = LM_ABI_VERSION;
        while (lm_next_event(world.node(0).ctx(), &event, nullptr, 0, nullptr) == LM_STATUS_OK) {
            if (event.kind == LM_EVENT_OPERATION && event.operation_id == operation) {
                if (event.reason != 0) return static_cast<Status>(event.reason);
                applied = true;
            }
        }
    }
    if (!applied) return Status::Expired;
    lm_join_request_t request{};
    request.struct_size = sizeof(request);
    request.abi_version = LM_ABI_VERSION;
    request.request_id.bytes[0] = 2;
    request.mode = LM_JOIN_NEW;
    lm_status_t accepted = LM_STATUS_AUTH_PENDING;
    for (unsigned i = 0; i < 200 && (accepted == LM_STATUS_AUTH_PENDING || accepted == LM_STATUS_BUSY); ++i) {
        accepted = lm_join(world.node(1).ctx(), &request, &operation);
        if (accepted == LM_STATUS_AUTH_PENDING || accepted == LM_STATUS_BUSY) run(5);
    }
    if (accepted != LM_STATUS_OK) return static_cast<Status>(accepted);
    for (unsigned i = 0; i < 8000; ++i) {
        run(5);
        const auto *entry = ledger.find(in.leaf_dc.device);
        if (world.node(1).ctx()->engine.identity().is_member() && entry != nullptr &&
            entry->state == root::EntryState::Active && entry->confirmed &&
            entry->assignment == in.ticket.new_generation) return Status::Ok;
    }
    return Status::Expired;
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 3 || (std::string(argv[1]) != "verify" && std::string(argv[1]) != "join")) return 2;
    Input in;
    Status status = sec::crypto_init();
    if (status == Status::Ok) status = verify(argv[2], in);
    if (status == Status::Ok && std::string(argv[1]) == "join") status = join(argv[2], in);
    std::cout << status_name(status) << '\n';
    return status == Status::Ok ? 0 : 1;
}
