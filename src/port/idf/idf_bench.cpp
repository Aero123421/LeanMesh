// BENCH / HIL ONLY (components/leanmesh/bench/leanmesh_bench.h): provisioning of a test board before lm_init.
// Compiled only with CONFIG_LEANMESH_BENCH_PROVISIONING (components/leanmesh/CMakeLists.txt), never part of the SDK
// source lists or a product image. The record contents and their order are those of the sim provisioning
// (src/port/sim/sim_provision.cpp, tests/native/issuer_driver.cpp); the writer is the SDK's own sealed-record layer.
//
// Key custody of a bench board: the scalar is generated here and stays on the board. Until the DeviceCredential of its
// public key arrives it waits in the `identity` partition (namespace "lmbench"), with the same protection as the
// identity record itself (NVS encryption when the build has it); it is erased once the identity record is committed.
#include <array>
#include <cstring>

#include <cstdio>

#include "bootloader_random.h"
#include "capi/context.hpp"
#include "core/member/credentials.hpp"
#include "core/member/records.hpp"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "leanmesh_bench.h"
#include "nvs.h"
#include "port/idf/idf_store.hpp"
#include "security/crypto.hpp"
#include "security/identity.hpp"
#include "store/record.hpp"
#ifdef LM_BUILD_PROFILE_ROOT
#include "root/ledger.hpp"
#include "serial/pairing.hpp"
#endif

namespace lm::idf {
namespace {

constexpr const char *k_partition = "identity";
constexpr const char *k_namespace = "lmbench";
constexpr const char *k_pending = "pk";

IdfStore g_store;
store::RecordJob g_job; // one bench call at a time (before lm_init): static, not on the caller's stack

// RAII NVS handle on the bench namespace.
class Pending {
  public:
    explicit Pending(nvs_open_mode_t mode) { err_ = nvs_open_from_partition(k_partition, k_namespace, mode, &h_); }
    ~Pending() {
        if (err_ == ESP_OK) {
            nvs_close(h_);
        }
    }
    Pending(const Pending &) = delete;
    Pending &operator=(const Pending &) = delete;
    [[nodiscard]] esp_err_t error() const { return err_; }
    // NotFound: no pending key.
    [[nodiscard]] Status read(std::array<uint8_t, 32> &scalar) const {
        if (err_ == ESP_ERR_NVS_NOT_FOUND) {
            return Status::NotFound;
        }
        if (err_ != ESP_OK) {
            return Status::StorageFailure;
        }
        size_t n = scalar.size();
        const esp_err_t e = nvs_get_blob(h_, k_pending, scalar.data(), &n);
        if (e == ESP_ERR_NVS_NOT_FOUND) {
            return Status::NotFound;
        }
        return e == ESP_OK && n == scalar.size() ? Status::Ok : Status::StorageFailure;
    }
    [[nodiscard]] Status write(const std::array<uint8_t, 32> &scalar) const {
        return err_ == ESP_OK && nvs_set_blob(h_, k_pending, scalar.data(), scalar.size()) == ESP_OK &&
                       nvs_commit(h_) == ESP_OK
                   ? Status::Ok
                   : Status::StorageFailure;
    }
    [[nodiscard]] Status erase() const {
        if (err_ != ESP_OK) {
            return Status::StorageFailure;
        }
        const esp_err_t e = nvs_erase_key(h_, k_pending);
        return (e == ESP_OK || e == ESP_ERR_NVS_NOT_FOUND) && nvs_commit(h_) == ESP_OK ? Status::Ok
                                                                                        : Status::StorageFailure;
    }

  private:
    nvs_handle_t h_ = 0;
    esp_err_t err_ = ESP_FAIL;
};

Status open_store() {
    LM_TRY(sec::crypto_init());
    return g_store.init(); // mounts identity/state (encrypted when the build has NVS encryption)
}

// NotFound: never provisioned.
Status identity_present() {
    g_job.arm(store::RecordJob::Op::Load, store::rec::identity);
    const Status st = store::record_load(g_store, g_job);
    sec::secure_zero(MutByteView{g_job.payload}); // the identity payload holds the scalar
    sec::secure_zero(MutByteView{g_job.scratch});
    return st;
}

Status commit(uint16_t id, uint8_t state, ByteView payload) {
    if (payload.size() > g_job.payload.size()) {
        return Status::NoCapacity;
    }
    g_job.arm(store::RecordJob::Op::Commit, id, state, payload.size());
    std::copy(payload.begin(), payload.end(), g_job.payload.begin());
    const Status st = store::record_commit(g_store, g_job);
    sec::secure_zero(MutByteView{g_job.payload});
    sec::secure_zero(MutByteView{g_job.scratch});
    return st;
}

void to_sec1(const sec::PublicKey &k, uint8_t out[65]) {
    out[0] = 0x04;
    std::memcpy(out + 1, k.x.data(), 32);
    std::memcpy(out + 33, k.y.data(), 32);
}

// What both roles check before writing anything: an unprovisioned board, its pending key, the trust anchor, and a
// DeviceCredential that the fleet issued for exactly that key. Out: the key (imported) and the credential.
struct Checked {
    std::array<uint8_t, 32> scalar{};
    sec::KeyHandle key;
    member::TrustAnchor trust;
    member::DeviceCredential dc;
    ~Checked() {
        sec::destroy_key(key);
        sec::secure_zero(MutByteView{scalar});
    }
};

Status check_common(const uint8_t trust88[88], ByteView device_cose, Checked &c) {
    LM_TRY(open_store());
    const Status present = identity_present();
    if (present == Status::Ok) {
        return Status::Conflict; // provisioned already: a bench board is erased (esptool) before a new identity
    }
    if (present != Status::NotFound) {
        return present;
    }
    LM_TRY(Pending(NVS_READONLY).read(c.scalar));
    LM_TRY(sec::import_signing_key(ByteView{c.scalar}, c.key));
    sec::PublicKey pub;
    LM_TRY(sec::public_key_of(c.key, pub));
    LM_TRY(member::decode_trust(ByteView{trust88, member::k_trust_bytes}, c.trust));
    LM_TRY(member::check_device_credential(c.trust, device_cose, c.dc));
    if (c.dc.key.x != pub.x || c.dc.key.y != pub.y) {
        return Status::AuthRejected; // a credential of another key
    }
    return Status::Ok;
}

// boot_incarnation first (a provisioned device must never look virgin), then identity and trust.
Status commit_identity(const Checked &c, ByteView device_cose) {
    const std::array<uint8_t, 8> zero{};
    LM_TRY(commit(store::rec::boot_incarnation, 0, ByteView{zero}));
    std::array<uint8_t, store::k_max_payload> buf{};
    std::size_t len = 0;
    Status st = member::encode_identity(ByteView{c.scalar}, device_cose, MutByteView{buf}, len);
    if (st == Status::Ok) {
        st = commit(store::rec::identity, 0, ByteView{buf.data(), len});
    }
    sec::secure_zero(MutByteView{buf});
    LM_TRY(st);
    LM_TRY(member::encode_trust(c.trust, MutByteView{buf}, len));
    return commit(store::rec::fleet_trust, 0, ByteView{buf.data(), len});
}

} // namespace
} // namespace lm::idf

extern "C" {

lm_status_t lmb_state(uint32_t *state) {
    using namespace lm;
    using namespace lm::idf;
    if (state == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    Status st = open_store();
    if (st == Status::Ok) {
        st = identity_present();
    }
    if (st == Status::Ok) {
        *state = LMB_PROVISIONED;
        return to_abi(Status::Ok);
    }
    if (st != Status::NotFound) {
        return to_abi(st);
    }
    std::array<uint8_t, 32> scalar{};
    st = Pending(NVS_READONLY).read(scalar);
    sec::secure_zero(MutByteView{scalar});
    if (st != Status::Ok && st != Status::NotFound) {
        return to_abi(st);
    }
    *state = st == Status::Ok ? LMB_KEY_PENDING : LMB_UNPROVISIONED;
    return to_abi(Status::Ok);
}

lm_status_t lmb_keygen(lmb_key_t *out) {
    using namespace lm;
    using namespace lm::idf;
    if (out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    Status st = open_store();
    if (st == Status::Ok) {
        st = identity_present();
        st = st == Status::Ok ? Status::Conflict : (st == Status::NotFound ? Status::Ok : st);
    }
    if (st != Status::Ok) {
        return to_abi(st);
    }
    std::array<uint8_t, 32> scalar{};
    sec::PublicKey pub;
    st = Pending(NVS_READONLY).read(scalar);
    if (st == Status::NotFound) {
        // The radio is off before lm_init: the hardware RNG is a true source only with this entropy source on
        // (docs/06 §8 "ESP32 entropyは公式条件でseedする").
        bootloader_random_enable();
        st = sec::generate_signing_key(scalar, pub);
        bootloader_random_disable();
        if (st == Status::Ok) {
            st = Pending(NVS_READWRITE).write(scalar);
        }
    } else if (st == Status::Ok) {
        sec::KeyHandle key;
        st = sec::import_signing_key(ByteView{scalar}, key);
        if (st == Status::Ok) {
            st = sec::public_key_of(key, pub);
        }
        sec::destroy_key(key);
    }
    sec::secure_zero(MutByteView{scalar});
    DeviceId id;
    if (st == Status::Ok) {
        st = sec::device_id_of(pub, id);
    }
    if (st == Status::Ok) {
        to_sec1(pub, out->public_key);
        std::memcpy(out->device_id, id.bytes.data(), id.bytes.size());
    }
    return to_abi(st);
}

lm_status_t lmb_provision_leaf(const uint8_t trust88[88], const uint8_t *device_cose, size_t device_len,
                               const uint8_t *ticket_cose, size_t ticket_len) {
    using namespace lm;
    using namespace lm::idf;
    if (trust88 == nullptr || device_cose == nullptr || ticket_cose == nullptr || device_len == 0 ||
        device_len > member::k_max_device_cose || ticket_len == 0 || ticket_len > store::k_max_payload) {
        return to_abi(Status::InvalidArgument);
    }
    const ByteView dc{device_cose, device_len};
    const ByteView ticket{ticket_cose, ticket_len};
    Checked c;
    Status st = check_common(trust88, dc, c);
    // The ticket's signature and target are the root's to check (the leaf holds no delegation yet); here only that
    // it is an initial ticket for this device.
    member::Envelope env;
    ByteView data;
    member::AssignmentTicket t;
    if (st == Status::Ok) {
        st = member::peek_signed(ticket, member::k_type_assignment_ticket, env, data);
    }
    if (st == Status::Ok) {
        st = member::decode_assignment_ticket(data, t);
    }
    if (st == Status::Ok && (t.device != c.dc.device || !t.source.is_zero() || t.expected_old != 0)) {
        st = Status::AuthRejected;
    }
    if (st == Status::Ok) {
        st = commit_identity(c, dc);
    }
    if (st == Status::Ok) {
        st = commit(store::rec::assignment_ticket, 0, ticket);
    }
    if (st == Status::Ok) {
        st = Pending(NVS_READWRITE).erase();
    }
    return to_abi(st);
}

lm_status_t lmb_provision_root(const uint8_t trust88[88], const uint8_t *device_cose, size_t device_len,
                               const uint8_t *delegation_cose, size_t delegation_len, const uint8_t host_id[32]) {
    using namespace lm;
#ifndef LM_BUILD_PROFILE_ROOT
    (void)trust88, (void)device_cose, (void)device_len, (void)delegation_cose, (void)delegation_len, (void)host_id;
    return to_abi(Status::Unsupported);
#else
    using namespace lm::idf;
    if (trust88 == nullptr || device_cose == nullptr || delegation_cose == nullptr || host_id == nullptr ||
        device_len == 0 || device_len > member::k_max_device_cose || delegation_len == 0 ||
        delegation_len > member::k_max_delegation_cose) {
        return to_abi(Status::InvalidArgument);
    }
    const ByteView dc{device_cose, device_len};
    const ByteView deleg{delegation_cose, delegation_len};
    DeviceId host;
    std::memcpy(host.bytes.data(), host_id, host.bytes.size());
    Checked c;
    Status st = check_common(trust88, dc, c);
    member::RootDelegation d;
    if (st == Status::Ok) {
        st = member::check_root_delegation(c.trust, deleg, d);
    }
    if (st == Status::Ok && (d.root != c.dc.device || d.key.x != c.dc.key.x || d.key.y != c.dc.key.y)) {
        st = Status::AuthRejected; // a delegation of another root
    }
    if (st == Status::Ok && host.is_zero()) {
        st = Status::InvalidArgument;
    }
    // The root's own MemberCredential of a new network (docs/12: stored term 0, so its first boot publishes 1),
    // signed here with the device key, as the root re-signs it at every boot (LocalIdentity::advance_term).
    std::array<uint8_t, member::k_max_member_cose> member_cose{};
    std::size_t member_len = 0;
    if (st == Status::Ok) {
        member::MemberCredential mc;
        mc.device = c.dc.device;
        mc.address = ShortAddr{1};
        mc.assignment = AssignmentGen{1};
        mc.membership = MembershipGen{1};
        mc.role = 2;
        mc.relay_allowed = true;
        mc.root_term = RootTerm{0};
        mc.lease_expires_root_ms = UINT64_MAX; // the root is its own time base (docs/12)
        st = sec::sha256(dc, mc.credential_hash);
        std::array<uint8_t, 256> data{};
        std::size_t dlen = 0;
        if (st == Status::Ok) {
            st = member::encode_member_credential(mc, MutByteView{data}, dlen);
        }
        member::Envelope env;
        env.type = member::k_type_member_credential;
        env.domain = d.domain;
        env.issuer = c.dc.device;
        env.revision = mc.membership.value();
        esp_fill_random(env.request.bytes.data(), env.request.bytes.size());
        if (st == Status::Ok) {
            st = member::issue_signed(c.key, env, ByteView{data.data(), dlen}, MutByteView{member_cose}, member_len);
        }
        member::MemberCredential back;
        if (st == Status::Ok) {
            st = member::check_member_credential(d, ByteView{member_cose.data(), member_len}, back);
        }
    }
    if (st == Status::Ok) {
        st = commit_identity(c, dc);
    }
    if (st == Status::Ok) {
        st = commit(store::rec::root_delegation, 0, deleg);
    }
    if (st == Status::Ok) {
        st = commit(store::rec::membership, member::k_membership_active, ByteView{member_cose.data(), member_len});
    }
    if (st == Status::Ok) {
        root::Manifest m; // the empty ledger of a new network: the only path that creates one (SEC-D5)
        m.domain = d.domain;
        std::array<uint8_t, root::k_manifest_bytes> buf{};
        std::size_t len = 0;
        st = root::encode_manifest(m, MutByteView{buf}, len);
        if (st == Status::Ok) {
            st = commit(store::rec::root_ledger, 0, ByteView{buf.data(), len});
        }
    }
    if (st == Status::Ok) {
        st = serial::write_paired_host(g_store, host);
    }
    if (st == Status::Ok) {
        st = Pending(NVS_READWRITE).erase();
    }
    return to_abi(st);
#endif
}

lm_status_t lmb_debug(lm_context_t *ctx, char *out, size_t cap) {
    using namespace lm;
    if (!capi::valid_ctx(ctx) || out == nullptr || cap == 0) {
        return to_abi(Status::InvalidArgument);
    }
    Engine &e = ctx->engine;
    const link::LinkStats &l = e.link().stats();
    const route::Mesh::Stats &m = e.mesh().stats();
    const link::EndStats &es = e.delivery().end_stats();
    int n = std::snprintf(out, cap,
                          "mesh=%u step=%u bcn_rx=%llu probes_tx=%llu reg=%llu lease=%llu ready=%llu suspect=%llu "
                          "attach_fail=%llu tx_busy=%llu | hs start=%llu ok=%llu fail=%llu ratelim=%llu busydrop=%llu "
                          "retx=%llu cred_rej=%llu cred_time=%llu bind_bad=%llu tx_rf_fail=%llu | rx ok=%llu "
                          "unknown_sid=%llu auth_fail=%llu no_id=%llu inadm=%llu lease_restr=%llu | end start=%llu "
                          "ok=%llu fail=%llu | nb=",
                          static_cast<unsigned>(e.mesh().state()), static_cast<unsigned>(e.mesh().attach_step_id()),
                          (unsigned long long)m.beacons_rx, (unsigned long long)m.probes_tx,
                          (unsigned long long)m.registers, (unsigned long long)m.leases, (unsigned long long)m.readies,
                          (unsigned long long)m.suspects, (unsigned long long)m.attach_failed,
                          (unsigned long long)m.tx_busy, (unsigned long long)l.hs_started,
                          (unsigned long long)l.hs_completed, (unsigned long long)l.hs_failed,
                          (unsigned long long)l.hs_rate_limited, (unsigned long long)l.hs_busy_drop,
                          (unsigned long long)l.hs_retransmits, (unsigned long long)l.cred_rejected,
                          (unsigned long long)l.cred_time_uncertain, (unsigned long long)l.bind_bad,
                          (unsigned long long)l.tx_rf_failed, (unsigned long long)l.rx_accepted,
                          (unsigned long long)l.rx_unknown_sid, (unsigned long long)l.rx_auth_fail,
                          (unsigned long long)l.rx_no_identity, (unsigned long long)l.rx_inadmissible,
                          (unsigned long long)l.rx_lease_restricted, (unsigned long long)es.started,
                          (unsigned long long)es.completed, (unsigned long long)es.failed);
    e.link().neighbors().for_each([&](Handle, link::Neighbor &nb) {
        if (n > 0 && static_cast<size_t>(n) < cap) {
            n += std::snprintf(out + n, cap - static_cast<size_t>(n), "%02x%02x@%u%s%s ", nb.mac.bytes[4], nb.mac.bytes[5],
                               static_cast<unsigned>(nb.address.value()), nb.join_only ? "J" : "",
                               nb.lease_uncertain ? "U" : "");
        }
    });
    // Stack high-water marks per SDK task (bytes never used since boot); the public diagnostics report only the least.
    if (n > 0 && static_cast<size_t>(n) < cap) {
        n += std::snprintf(out + n, cap - static_cast<size_t>(n), "| stack_free");
        for (const char *name : {"lm_owner", "lm_worker", "lm_usb", "main"}) {
            const TaskHandle_t t = xTaskGetHandle(name);
            if (t != nullptr && n > 0 && static_cast<size_t>(n) < cap) {
                n += std::snprintf(out + n, cap - static_cast<size_t>(n), " %s=%u", name,
                                   static_cast<unsigned>(uxTaskGetStackHighWaterMark(t)));
            }
        }
        n += std::snprintf(out + n, cap - static_cast<size_t>(n), " ");
    }
    if (n > 0 && static_cast<size_t>(n) < cap) {
        n += std::snprintf(out + n, cap - static_cast<size_t>(n), "| cand=");
    }
    e.mesh().for_each_candidate([&](const MacAddr &mac, uint16_t addr, uint8_t entries, uint8_t streak, uint8_t fails,
                                    bool target) {
        if (n > 0 && static_cast<size_t>(n) < cap) {
            n += std::snprintf(out + n, cap - static_cast<size_t>(n), "%02x%02x@%u/n%u/rf%u/f%u%s ", mac.bytes[4],
                               mac.bytes[5], static_cast<unsigned>(addr), static_cast<unsigned>(entries),
                               static_cast<unsigned>(streak), static_cast<unsigned>(fails), target ? "*" : "");
        }
    });
    return to_abi(Status::Ok);
}

} // extern "C"
