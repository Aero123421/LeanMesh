// Build gate and (never flashed by any script) known-answer check of the whole security path on a
// target: PSA key generation, COSE_Sign1, a complete EDHOC handshake between two in-RAM identities
// through the job bodies, and a record round trip. Referenced only by firmware/crypto_link_check;
// the linker drops it from every other image. Not a diagnostic that runs in products.
#include <array>

#include "core/ports.hpp"
#include "security/cose_sign1.hpp"
#include "security/crypto.hpp"
#include "security/handshake.hpp"
#include "security/identity.hpp"
#include "security/record.hpp"

namespace lm::sec {
namespace {

class NullStore final : public port::Store {
  public:
    Status slot_read(uint16_t, uint8_t, MutByteView, std::size_t &) override { return Status::StorageFailure; }
    Status slot_write(uint16_t, uint8_t, ByteView) override { return Status::StorageFailure; }
    Status slot_erase(uint16_t, uint8_t) override { return Status::StorageFailure; }
    uint32_t journal_segment_bytes() const override { return 0; }
    uint32_t journal_segments() const override { return 0; }
    Status journal_read(uint32_t, MutByteView) override { return Status::StorageFailure; }
    Status journal_write(uint32_t, ByteView) override { return Status::StorageFailure; }
    Status journal_erase(uint32_t) override { return Status::StorageFailure; }
};

struct Node {
    KeyHandle key;
    PublicKey pub;
    DeviceId id;
    std::array<uint8_t, k_ccs_max_bytes> ccs{};
    std::size_t ccs_len = 0;
};

Status make_node(Node &n, ByteView subject) {
    std::array<uint8_t, 32> scalar{};
    LM_TRY(generate_signing_key(scalar, n.pub));
    const Status st = import_signing_key(ByteView{scalar.data(), scalar.size()}, n.key);
    secure_zero(MutByteView{scalar.data(), scalar.size()});
    LM_TRY(st);
    LM_TRY(device_id_of(n.pub, n.id));
    return ccs_encode(subject, n.pub, MutByteView{n.ccs.data(), n.ccs.size()}, n.ccs_len);
}

Status step(NullStore &store, HandshakeSlot &s, HsStep which, ByteView in = ByteView{}) {
    LM_TRY(s.prepare(which, in));
    port::JobEnv env{store};
    return s.complete(HandshakeSlot::run_job(env, &s));
}

Status loopback() {
    static NullStore store;
    static HandshakeSlot init;
    static HandshakeSlot resp;
    Node a;
    Node b;
    const uint8_t sa[] = {'a'};
    const uint8_t sb[] = {'b'};
    LM_TRY(make_node(a, ByteView{sa, 1}));
    LM_TRY(make_node(b, ByteView{sb, 1}));
    const ByteView pa[1] = {ByteView{a.ccs.data(), a.ccs_len}};
    const ByteView pb[1] = {ByteView{b.ccs.data(), b.ccs_len}};
    LM_TRY(init.begin(HsRole::Initiator, a.key, pa[0], pb, 1));
    LM_TRY(resp.begin(HsRole::Responder, b.key, pb[0], pa, 1));
    LM_TRY(step(store, init, HsStep::M1Compose));
    LM_TRY(step(store, resp, HsStep::M1Process, init.output()));
    LM_TRY(step(store, resp, HsStep::M2Compose));
    LM_TRY(step(store, init, HsStep::M2Process, resp.output()));
    LM_TRY(step(store, init, HsStep::M3Compose));
    LM_TRY(step(store, resp, HsStep::M3Process, init.output()));
    LM_TRY(step(store, resp, HsStep::M4Compose));
    LM_TRY(step(store, init, HsStep::M4Process, resp.output()));
    SessionContext ctx;
    ctx.purpose = Purpose::Link;
    ctx.initiator = a.id;
    ctx.responder = b.id;
    LM_TRY(init.set_context(ctx));
    LM_TRY(resp.set_context(ctx));
    LM_TRY(step(store, init, HsStep::Export));
    LM_TRY(step(store, resp, HsStep::Export));
    RecordKeys ki;
    RecordKeys kr;
    LM_TRY(init.take_keys(ki));
    LM_TRY(resp.take_keys(kr));

    // Record round trip and a COSE object signed by the initiator's key.
    RecordSession tx;
    RecordSession rx;
    LM_TRY(tx.install(std::move(ki)));
    LM_TRY(rx.install(std::move(kr)));
    Sha256Digest h{};
    LM_TRY(context_hash(ctx, h));
    uint64_t counter = 0;
    LM_TRY(tx.next_counter(counter));
    const uint8_t msg[] = {1, 2, 3};
    std::array<uint8_t, 3 + k_aead_tag_bytes> ct{};
    LM_TRY(tx.seal(counter, ByteView{h.data(), h.size()}, ByteView{msg, 3}, MutByteView{ct.data(), ct.size()}));
    std::array<uint8_t, 3> pt{};
    std::size_t len = 0;
    ReplayVerdict verdict{};
    LM_TRY(rx.open(counter, ByteView{h.data(), h.size()}, ByteView{ct.data(), ct.size()},
                   MutByteView{pt.data(), pt.size()}, len, verdict));
    rx.accept(counter);
    std::array<uint8_t, 160> cose{};
    std::size_t cose_len = 0;
    LM_TRY(sign1_create(a.key, a.id, ByteView{msg, 3}, MutByteView{cose.data(), cose.size()}, cose_len));
    Sign1View view;
    const Status verified = sign1_verify(a.pub, ByteView{cose.data(), cose_len}, view);
    destroy_key(a.key);
    destroy_key(b.key);
    tx.wipe();
    rx.wipe();
    return verified;
}

} // namespace
} // namespace lm::sec

extern "C" int lm_security_link_check(void) {
    if (lm::sec::crypto_init() != lm::Status::Ok) {
        return -1;
    }
    return lm::sec::loopback() == lm::Status::Ok ? 0 : -2;
}
