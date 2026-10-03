#include "root/backup.hpp"
#include "root/ledger.hpp"

#include <algorithm>

#include "core/codec.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"

namespace lm::root::backup {
namespace {

static_assert(k_slots == k_ledger_slots && k_entry_base == k_rec_ledger_base, "backup.hpp mirrors the ledger's layout");
constexpr uint64_t k_u63 = 0x7FFFFFFFFFFFFFFFULL;
constexpr char k_chain_label[] = {'L', 'M', 'B', 'K', '1'};
// label + id + state + length + the largest record payload + next.
constexpr std::size_t k_link_max = sizeof k_chain_label + 2 + 1 + 2 + store::k_max_payload + 32;

} // namespace

std::size_t Header::count() const {
    return static_cast<std::size_t>(__builtin_popcountll(entries)) +
           static_cast<std::size_t>(__builtin_popcount(extras)) + 1U;
}

Status encode_header(const Header &h, MutByteView out, std::size_t &len) {
    if (h.seq == 0 || h.seq > k_u63 || h.generation > k_u63 || h.change > k_u63 || h.extras > 7 ||
        h.delegation.empty() || h.delegation.size() > member::k_max_delegation_cose) {
        return Status::InvalidArgument;
    }
    wire::CborWriter w{out};
    w.array(8);
    w.uint(h.seq);
    w.uint(h.term);
    w.uint(h.generation);
    w.bytes(h.delegation);
    w.uint(h.change);
    w.uint(h.entries);
    w.uint(h.extras);
    w.bytes(ByteView{h.head});
    len = w.size();
    return w.finish();
}

Status decode_header(ByteView data, Header &out) {
    wire::CborReader r{data};
    Header h;
    (void)r.array(8, 8);
    h.seq = r.uint_in(1, k_u63);
    h.term = static_cast<uint32_t>(r.uint_in(0, 0xFFFFFFFFULL));
    h.generation = r.uint_in(0, k_u63);
    h.delegation = r.bstr(1, member::k_max_delegation_cose);
    h.change = r.uint_in(0, k_u63);
    h.entries = r.uint_in(0, ~uint64_t{0});
    h.extras = static_cast<uint8_t>(r.uint_in(0, 7));
    const ByteView head = r.bstr(32, 32);
    LM_TRY(r.finish());
    std::copy(head.begin(), head.end(), h.head.begin());
    out = h;
    return Status::Ok;
}

uint16_t element_id(const Header &h, std::size_t index) {
    if (index >= h.count()) {
        return 0;
    }
    static constexpr struct {
        uint8_t bit;
        uint16_t id;
    } k_extras[] = {{k_extra_floors, store::rec::revocation_floors},
                    {k_extra_groups, store::rec::root_groups},
                    {k_extra_policy, store::rec::policy}};
    for (const auto &x : k_extras) {
        if ((h.extras & x.bit) != 0) {
            if (index == 0) {
                return x.id;
            }
            --index;
        }
    }
    uint64_t mask = h.entries;
    for (; mask != 0; mask &= mask - 1U) {
        if (index == 0) {
            return static_cast<uint16_t>(k_entry_base + __builtin_ctzll(mask));
        }
        --index;
    }
    return store::rec::root_ledger; // the manifest, always last
}

Status link(uint16_t id, uint8_t state, ByteView payload, const Sha256Digest &next, Sha256Digest &out) {
    if (payload.size() > store::k_max_payload) {
        return Status::InvalidArgument;
    }
    std::array<uint8_t, k_link_max> buf{};
    Writer w{MutByteView{buf}};
    w.bytes(ByteView{reinterpret_cast<const uint8_t *>(k_chain_label), sizeof k_chain_label});
    w.u16be(id);
    w.u8(state);
    w.u16be(static_cast<uint16_t>(payload.size()));
    w.bytes(payload);
    w.bytes(ByteView{next});
    LM_TRY(w.finish());
    return sec::sha256(w.written(), out);
}

} // namespace lm::root::backup
