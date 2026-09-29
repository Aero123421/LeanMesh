#include "core/wire/control.hpp"

#include <algorithm>

#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "gen/registry.hpp"

namespace lm::wire {
namespace {

constexpr uint64_t k_u32 = 0xFFFFFFFFULL;
constexpr uint64_t k_u63 = 0x7FFFFFFFFFFFFFFFULL;
constexpr uint64_t k_u64 = UINT64_MAX;

// Declarative CDDL: one Field per array element of a control-data item.
enum class K : uint8_t { Uint, U63, U64, Bytes, Text, Bool, List, Tuple, Nullable, CoseKey, Soc };
struct Field {
    K kind;
    uint8_t n; // Tuple: element count
    uint32_t lo; // Uint: value range; Bytes/Text: size range; List: count range
    uint32_t hi;
    const Field *sub; // List: element; Tuple: elements; Nullable: inner
};

constexpr Field U(uint32_t lo, uint32_t hi) { return {K::Uint, 0, lo, hi, nullptr}; }
constexpr Field Bs(uint32_t lo, uint32_t hi) { return {K::Bytes, 0, lo, hi, nullptr}; }
constexpr Field Tx(uint32_t lo, uint32_t hi) { return {K::Text, 0, lo, hi, nullptr}; }

constexpr Field kU32 = U(0, 0xFFFFFFFFU);
constexpr Field kU63 = {K::U63, 0, 0, 0, nullptr};
constexpr Field kU64 = {K::U64, 0, 0, 0, nullptr};
constexpr Field kId16 = Bs(16, 16);
constexpr Field kId32 = Bs(32, 32);
constexpr Field kBool = {K::Bool, 0, 0, 0, nullptr};
constexpr Field kKey = {K::CoseKey, 0, 0, 0, nullptr};
constexpr Field kSoc = {K::Soc, 0, 0, 0, nullptr};
constexpr Field kAddr = U(1, 65534);
constexpr Field kChannel = U(1, 13);
constexpr Field kNullId16 = {K::Nullable, 0, 0, 0, &kId16};

constexpr Field kAddrElem[] = {kAddr};
constexpr Field kExpectedEntry[] = {kId32, kU63, kId32, kBool};
constexpr Field kGroupTarget[] = {kId32, kU63, kU63};
constexpr Field kEntryTuple = {K::Tuple, 4, 0, 0, kExpectedEntry};
constexpr Field kTargetTuple = {K::Tuple, 3, 0, 0, kGroupTarget};
constexpr Field kAddrs = {K::List, 0, 1, 21, kAddrElem};
constexpr Field kEntries = {K::List, 0, 0, 8, &kEntryTuple};
constexpr Field kTargets = {K::List, 0, 0, 16, &kTargetTuple};

constexpr Field s_device_credential[] = {kId32, kKey, kId16, Tx(1, 48), kU63, kId32};
constexpr Field s_root_delegation[] = {kId16, kId32, kKey, kId16, kU63, U(0, 63)};
constexpr Field s_assignment_ticket[] = {kId32, kId16, kId16, kId16, kId32, kU63,
                                         kU63,  kId16, U(0, 1), kId16, kId32};
constexpr Field s_member_credential[] = {kId32, kAddr, kU63, kU63, U(0, 2),
                                         kBool, kU32,  kU64, kId32, kId32};
constexpr Field s_expected_set[] = {U(0, 15), U(1, 16), kId32, kEntries};
constexpr Field s_join_request[] = {Bs(1, 1024), Bs(1, 1024), kId16, kU64};
constexpr Field s_join_prepare[] = {Bs(1, 1024), kId32, kAddr, kU63, kU32, U(1, 120000)};
constexpr Field s_hash_gen[] = {kId32, kU63}; // JoinStored, JoinCommit, JoinActive
constexpr Field s_revoke[] = {kId32, kU63, kU63, kU32, kU63};
constexpr Field s_policy[] = {kU63, kU63, kId32, Bs(1, 3072)};
constexpr Field s_route_register[] = {kId32, kU63, kU63, kU32, kAddr, kAddrs, kU32, kId16};
constexpr Field s_route_lease[] = {kId32, kU32, kU32, kAddrs, kU64};
constexpr Field s_route_query[] = {kId32, kU32};
constexpr Field s_probe[] = {kId16, kAddr, kAddr, kBool, U(0, 255), kU63};
constexpr Field s_time_request[] = {kId16, kU32, kU64};
constexpr Field s_time_response[] = {kId16, kU32, kU64, kU64, kU64};
constexpr Field s_channel_plan[] = {kId16, U(0, 2), kU32, kU32, kChannel, kChannel,
                                    kId32, kU64,    kU32, kU32, kU63,      kId32};
constexpr Field s_channel_receipt[] = {kId16, kId32, kId32, U(0, 3), kU32, kU32};
constexpr Field s_recovery_beacon[] = {kU32, kU32, kChannel, kId16, kId32, kId32};
constexpr Field s_delivery_receipt[] = {kId16, kId32, U(0, 6), kU32, kU32, Bs(0, 32)};
constexpr Field s_ota[] = {kSoc,  Tx(1, 32), U(1, 1900544), kId32, Tx(1, 32),
                           kU32,  kU32,      kU32,          kU32,  U(4096, 4096)};
constexpr Field s_leave[] = {kId32, U(0, 1), U(0, 30000)};
constexpr Field s_sleep[] = {kId32, kU63,         kU63,         kU32,
                             kU63,  U(0, 2),      U(0, 2),      kU64,
                             kU64,  U(0, 86400000), U(0, 65535), U(1, 86400000)};
constexpr Field s_power_policy[] = {kId32, kU63, kU63, kId32, Bs(1, 1024)};
constexpr Field s_commissioning[] = {kId16, kU32, kU63, kU64, kU64, U(1, 64), U(1, 3), kU63};
constexpr Field s_handover[] = {kId16, kId32, kId32, kU63, kU63, kId32, kU32, U(0, 1)};
constexpr Field s_group_snapshot[] = {kU32, kU63, kId16, kId32, U(0, 64), U(0, 3), kId32, kTargets};
constexpr Field s_group_request[] = {kU32, kU63, U(0, 3), kNullId16};

struct TypeShape {
    uint8_t type;
    const Field *fields;
    uint8_t count;
};
#define LM_SHAPE(t, arr) {t, arr, static_cast<uint8_t>(sizeof(arr) / sizeof((arr)[0]))}
// The mandatory type -> data mapping (control.cddl `control-data`). 22..24 are absent on purpose.
constexpr TypeShape k_shapes[] = {
    LM_SHAPE(1, s_device_credential),   LM_SHAPE(2, s_root_delegation),
    LM_SHAPE(3, s_assignment_ticket),   LM_SHAPE(4, s_member_credential),
    LM_SHAPE(5, s_expected_set),        LM_SHAPE(6, s_join_request),
    LM_SHAPE(7, s_join_prepare),        LM_SHAPE(8, s_hash_gen),
    LM_SHAPE(9, s_hash_gen),            LM_SHAPE(10, s_hash_gen),
    LM_SHAPE(11, s_revoke),             LM_SHAPE(12, s_policy),
    LM_SHAPE(13, s_route_register),     LM_SHAPE(14, s_route_lease),
    LM_SHAPE(15, s_route_query),        LM_SHAPE(16, s_probe),
    LM_SHAPE(17, s_time_request),       LM_SHAPE(18, s_time_response),
    LM_SHAPE(19, s_channel_plan),       LM_SHAPE(20, s_channel_receipt),
    LM_SHAPE(21, s_recovery_beacon),    LM_SHAPE(25, s_delivery_receipt),
    LM_SHAPE(26, s_ota),                LM_SHAPE(27, s_leave),
    LM_SHAPE(28, s_sleep),              LM_SHAPE(29, s_power_policy),
    LM_SHAPE(30, s_commissioning),      LM_SHAPE(31, s_handover),
    LM_SHAPE(32, s_group_snapshot),     LM_SHAPE(33, s_group_request),
};
#undef LM_SHAPE

const TypeShape *find_shape(uint8_t type) {
    for (const TypeShape &s : k_shapes) {
        if (s.type == type) {
            return &s;
        }
    }
    return nullptr;
}

void read_field(CborReader &r, const Field &f);

void read_tuple(CborReader &r, const Field *fields, std::size_t n) {
    (void)r.array(n, n);
    for (std::size_t i = 0; i < n && r.ok(); ++i) {
        read_field(r, fields[i]);
    }
}

// {1: 2, -1: 1, -2: x32, -3: y32} in deterministic key order.
void read_cose_key(CborReader &r) {
    r.map_exact(4);
    (void)r.uint_in(1, 1);
    (void)r.uint_in(2, 2);
    (void)r.int_in(-1, -1);
    (void)r.uint_in(1, 1);
    (void)r.int_in(-2, -2);
    (void)r.bstr(32, 32);
    (void)r.int_in(-3, -3);
    (void)r.bstr(32, 32);
}

void read_soc(CborReader &r) {
    const ByteView s = r.tstr(7, 7);
    constexpr char names[4][8] = {"esp32c3", "esp32s3", "esp32c5", "esp32c6"};
    bool match = false;
    for (const auto &n : names) {
        match = match || (r.ok() && std::equal(s.begin(), s.end(), n));
    }
    if (!match) {
        r.fail();
    }
}

void read_field(CborReader &r, const Field &f) {
    switch (f.kind) {
    case K::Uint:
        (void)r.uint_in(f.lo, f.hi);
        break;
    case K::U63:
        (void)r.uint_in(0, k_u63);
        break;
    case K::U64:
        (void)r.uint_in(0, k_u64);
        break;
    case K::Bytes:
        (void)r.bstr(f.lo, f.hi);
        break;
    case K::Text:
        (void)r.tstr(f.lo, f.hi);
        break;
    case K::Bool:
        (void)r.boolean();
        break;
    case K::List: {
        const std::size_t n = r.array(f.lo, f.hi);
        for (std::size_t i = 0; i < n && r.ok(); ++i) {
            // List elements are either a scalar Field (n == 0 here) or a Tuple described by *sub.
            read_field(r, f.sub[0]);
        }
        break;
    }
    case K::Tuple:
        read_tuple(r, f.sub, f.n);
        break;
    case K::Nullable:
        if (!r.try_null()) {
            read_field(r, *f.sub);
        }
        break;
    case K::CoseKey:
        read_cose_key(r);
        break;
    case K::Soc:
        read_soc(r);
        break;
    }
}

// Reads a 32-byte id / 16-byte id into a fixed array.
template <std::size_t N> void read_id(CborReader &r, std::array<uint8_t, N> &out) {
    const ByteView v = r.bstr(N, N);
    if (r.ok()) {
        std::copy(v.begin(), v.end(), out.begin());
    }
}

constexpr uint8_t k_cose_protected_prefix[] = {0xA2, 0x01, 0x26, 0x04, 0x58, 0x20};

} // namespace

bool is_signed_control_type(uint8_t type) {
    return std::find(gen::k_signed_control_types.begin(), gen::k_signed_control_types.end(),
                     type) != gen::k_signed_control_types.end();
}

bool is_control_type_defined(uint8_t type) { return find_shape(type) != nullptr; }

Status decode_control_body(ByteView in, ControlCarrier carrier, ControlBody &out) {
    LM_TRY(cbor_validate(in));
    CborReader r{in};
    (void)r.array(7, 7);
    const uint64_t type = r.uint_in(0, k_u32);
    const uint64_t version = r.uint_in(0, k_u32);
    if (!r.ok()) {
        return Status::BadFrame;
    }
    const TypeShape *shape = type <= 255 ? find_shape(static_cast<uint8_t>(type)) : nullptr;
    if (shape == nullptr || version != k_control_version) {
        return Status::Unsupported;
    }
    ControlBody body;
    body.type = shape->type;
    read_id(r, body.request_id);
    read_id(r, body.domain);
    body.revision = r.uint_in(0, k_u63);
    read_id(r, body.issuer);
    const std::size_t data_start = r.position();
    read_tuple(r, shape->fields, shape->count);
    LM_TRY(r.finish());
    body.data = in.subspan(data_start, in.size() - data_start);
    if (is_signed_control_type(body.type) != (carrier == ControlCarrier::Signed)) {
        return Status::AuthRejected;
    }
    out = body;
    return Status::Ok;
}

Status encode_control_body(const ControlBody &body, MutByteView out, std::size_t &len) {
    CborWriter w{out};
    w.array(7);
    w.uint(body.type);
    w.uint(body.version);
    w.bytes(ByteView{body.request_id});
    w.bytes(ByteView{body.domain});
    w.uint(body.revision);
    w.bytes(ByteView{body.issuer});
    w.raw(body.data);
    len = w.size();
    return w.finish();
}

Status decode_cose_sign1(ByteView in, CoseSign1 &out) {
    if (in.size() > k_cose_max_bytes || in.empty() || in[0] != 0xD2) {
        return Status::BadFrame;
    }
    const ByteView body = in.from(1);
    LM_TRY(cbor_validate(body));
    CborReader r{body};
    (void)r.array(4, 4);
    CoseSign1 c;
    c.protected_bytes = r.bstr(sizeof k_cose_protected_prefix + 32, sizeof k_cose_protected_prefix + 32);
    r.map_exact(0);
    c.payload = r.bstr(0, k_cose_max_bytes);
    c.signature = r.bstr(64, 64);
    LM_TRY(r.finish());
    // protected == {1: -7, 4: kid}: exactly the deterministic encoding with a 32-byte kid.
    if (!std::equal(std::begin(k_cose_protected_prefix), std::end(k_cose_protected_prefix),
                    c.protected_bytes.begin())) {
        return Status::BadFrame;
    }
    std::copy(c.protected_bytes.begin() + sizeof k_cose_protected_prefix, c.protected_bytes.end(),
              c.kid.begin());
    out = c;
    return Status::Ok;
}

Status encode_cose_sign1(const std::array<uint8_t, 32> &kid, ByteView payload, ByteView signature64,
                         MutByteView out, std::size_t &len) {
    if (signature64.size() != 64) {
        return Status::InvalidArgument;
    }
    CborWriter w{out};
    w.tag(18);
    w.array(4);
    w.bytes_head(sizeof k_cose_protected_prefix + kid.size());
    w.raw(ByteView{k_cose_protected_prefix, sizeof k_cose_protected_prefix});
    w.raw(ByteView{kid});
    w.map(0);
    w.bytes(payload);
    w.bytes(signature64);
    len = w.size();
    return w.finish();
}

Status sig_structure_prefix(ByteView protected_bytes, std::size_t payload_len, MutByteView out,
                            std::size_t &len) {
    CborWriter w{out};
    w.array(4);
    w.text(ascii("Signature1"));
    w.bytes(protected_bytes);
    w.bytes(ascii("LM1-CONTROL"));
    // bstr head of the payload only; the payload bytes follow in the caller's hash/sign input.
    w.bytes_head(payload_len);
    len = w.size();
    return w.finish();
}

} // namespace lm::wire
