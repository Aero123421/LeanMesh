#include <cstring>

#include "core/delivery/types.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"

namespace lm::delivery {
namespace {
// CBOR head bytes of the array + fixed fields, plus one bstr head for the payload.
constexpr std::size_t k_intent_fixed = 1 + 34 + 34 + 18 + 3 + 1 + 1 + 1 + 5 + 9 + 3;
} // namespace

Status intent_hash(const IntentFields &f, Sha256Digest &out) {
    if (f.payload.size() > wire::data_capacity(1)) {
        return Status::NoCapacity;
    }
    std::array<uint8_t, k_intent_fixed + wire::data_capacity(1)> buf{};
    wire::CborWriter w{MutByteView{buf}};
    w.array(10);
    w.bytes(f.origin.view());
    w.bytes(f.target.view());
    w.bytes(f.domain.view());
    w.uint(f.app_port);
    w.uint(f.delivery);
    w.uint(f.storage);
    w.uint(f.priority);
    w.uint(f.expires_root_ms == 0 ? 0 : f.root_term);
    w.uint(f.expires_root_ms);
    w.bytes(f.payload);
    LM_TRY(w.finish());
    return sec::sha256(w.written(), out);
}

// receipt = [message-id bstr16, intent-hash bstr32, evidence 0..6, reason u32, sequence u32,
//            application-result bstr 0..32]
Status encode_receipt(const Receipt &r, MutByteView out, std::size_t &len) {
    if (r.result_len > k_result_bytes || static_cast<uint8_t>(r.evidence) > 6) {
        return Status::InvalidArgument;
    }
    wire::CborWriter w{out};
    w.array(6);
    w.bytes(ByteView{r.message_id});
    w.bytes(ByteView{r.intent_hash});
    w.uint(static_cast<uint8_t>(r.evidence));
    w.uint(r.reason);
    w.uint(r.sequence);
    w.bytes(ByteView{r.result.data(), r.result_len});
    LM_TRY(w.finish());
    len = w.size();
    return Status::Ok;
}

Status decode_receipt(ByteView in, Receipt &out) {
    LM_TRY(wire::cbor_validate(in));
    wire::CborReader r{in};
    (void)r.array(6, 6);
    Receipt v;
    const ByteView id = r.bstr(16, 16);
    const ByteView hash = r.bstr(32, 32);
    const uint64_t evidence = r.uint_in(0, 6);
    const uint64_t reason = r.uint_in(0, 0xFFFFFFFFULL);
    const uint64_t seq = r.uint_in(0, 0xFFFFFFFFULL);
    const ByteView result = r.bstr(0, k_result_bytes);
    LM_TRY(r.finish());
    std::memcpy(v.message_id.data(), id.data(), 16);
    std::memcpy(v.intent_hash.data(), hash.data(), 32);
    v.evidence = static_cast<ReceiptEv>(evidence);
    v.reason = static_cast<uint32_t>(reason);
    v.sequence = static_cast<uint32_t>(seq);
    v.result_len = static_cast<uint8_t>(result.size());
    if (!result.empty()) {
        std::memcpy(v.result.data(), result.data(), result.size());
    }
    out = v;
    return Status::Ok;
}

} // namespace lm::delivery
