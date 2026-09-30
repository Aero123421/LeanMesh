// Shared by the ledger's translation units (ledger.cpp: plumbing, boot, timers; ledger_join.cpp: the join
// transaction; ledger_ops.cpp: leave and expected entries).
#pragma once

#include <cstddef>

#include "root/ledger.hpp"

namespace lm::root::detail {

// Entry record payload: confirmed u8 | assignment u64 | membership u64 | consumed u64 (SEC-D4) | device 32 |
// request 16 | hash 32 | [MemberCredential COSE]; the record's state byte is the EntryState.
inline constexpr std::size_t k_entry_head = 1 + 8 + 8 + 8 + 32 + 16 + 32;
static_assert(k_entry_head + member::k_max_member_cose <= store::k_max_payload, "entry record fits");
// The MemberCredential COSE waits at the credential buffer's tail while the JoinPrepare is built at its head.
inline constexpr std::size_t k_cose_off = 624;
static_assert(k_cose_off + member::k_max_member_cose <= 1024, "tail fits");

inline constexpr Duration k_busy_retry = Duration::from_ms(50);
inline constexpr Duration k_session_wait = Duration::from_s(30); // JOIN_ONLY session up, no JoinRequest yet
inline constexpr Duration k_offer_gap = Duration::from_ms(100);  // at most one discovery offer per gap
inline constexpr Duration k_linger = Duration::from_ms(3500);    // refusal / final ack retransmit window

[[nodiscard]] Status encode_entry(const Entry &e, bool confirmed, ByteView cose, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_entry(const store::RecordJob &rec, Entry &out, ByteView &cose);

// The manifest record (store::rec::root_ledger, SEC-D5) binds the ledger to its domain and says which slots
// ever held an entry record; its encoding is in ledger.hpp (Manifest) because provisioning writes it too.
[[nodiscard]] Status decode_manifest(ByteView payload, Manifest &out);

// [FIX5-D6] store::rec::commissioning_window (layout at WindowRecord). A record of another layout (the S18 one:
// window id + count, 17 B) does not decode: pre-release, no migration - the root is RECOVERY_REQUIRED at load.
[[nodiscard]] Status encode_window_record(const WindowRecord &r, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_window_record(ByteView payload, WindowRecord &out);

// [FIX8-D12] store::rec::policy: the join mode lm_policy_set committed, and how many such changes were committed (the
// ledger's share of the one policy revision). An unreadable record keeps the root CLOSED (never the default mode).
inline constexpr uint8_t k_policy_version = 1;
[[nodiscard]] Status encode_policy(JoinMode mode, uint64_t changes, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_policy(ByteView payload, JoinMode &mode, uint64_t &changes);

// [FIX5-D1] Reads of the retirement record after its commit failed (it may have reached the Flash): this many, this far
// apart; the lifecycle install stays open meanwhile (other installs are BUSY), so the whole wait stays short.
inline constexpr uint8_t k_retire_checks = 3;
inline constexpr Duration k_retire_check_gap = Duration::from_ms(1000);
// [FIX5-D2, FIX8-D1] Repairs of entries whose (stricter) RAM state is ahead of their record, and of the floors record:
// bounded retry, this many failures in a row with a doubling gap from k_recon_gap (1+2+4+8 s: a store that answers again
// within about 15 s is caught up in this boot). RAM refuses meanwhile; what never became durable is decided by the
// records at the next boot (a revocation that answered RECOVERY_REQUIRED is installed again).
inline constexpr uint8_t k_recon_tries = 5;
inline constexpr Duration k_recon_gap = Duration::from_ms(1000);

} // namespace lm::root::detail
