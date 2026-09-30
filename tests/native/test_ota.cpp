// OTA software part (S19, T23): the signed manifest check (O02), the rollback state machine with its boot
// decisions, and the crash consistency of the state record (sim power cut at every Flash call of every state
// commit). SIM AND HOST ONLY: no image is written, no boot target switched, no rollback taken on a device. O01 (power
// cut during an image write / around the boot switch) and O03 (crash of an unconfirmed image, schema rollback) need
// hardware and stay NOT_RUN. Manifests come from the TEST-ONLY fleet issuer.
#include <array>
#include <cstring>
#include <vector>

#include "core/ota/ota.hpp"
#include "core/wire/cbor.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_store.hpp"
#include "security/crypto.hpp"
#include "store/record.hpp"

using namespace lm;
using namespace lm::ota;
using fleet::Bytes;

namespace {

ByteView view(const Bytes &b) { return ByteView{b.data(), b.size()}; }

struct Spec {
    const char *soc = "esp32c3";
    const char *board = "devkit";
    uint32_t image_bytes = 1'000'000;
    uint32_t security = 6;
    uint32_t schema_min = 1, schema_max = 2;
    uint32_t loader_min = 2;
    uint64_t block = 4096;
    uint8_t sha_fill = 0xA5;
    const char *version = "1.2.0";
};

Bytes manifest_data(const Spec &s) {
    Bytes buf(200);
    wire::CborWriter w{MutByteView{buf.data(), buf.size()}};
    w.array(10);
    w.text(ByteView{reinterpret_cast<const uint8_t *>(s.soc), std::strlen(s.soc)});
    w.text(ByteView{reinterpret_cast<const uint8_t *>(s.board), std::strlen(s.board)});
    w.uint(s.image_bytes);
    std::array<uint8_t, 32> sha{};
    sha.fill(s.sha_fill);
    w.bytes(ByteView{sha});
    w.text(ByteView{reinterpret_cast<const uint8_t *>(s.version), std::strlen(s.version)});
    w.uint(s.security);
    w.uint(s.schema_min);
    w.uint(s.schema_max);
    w.uint(s.loader_min);
    w.uint(s.block);
    buf.resize(w.size());
    return buf;
}

member::Envelope envelope(const fleet::Fleet &f, uint8_t type = k_type_manifest) {
    member::Envelope e;
    e.type = type;
    e.issuer = f.trust().key_id;
    e.revision = 1;
    e.request.bytes.fill(0x26);
    return e;
}

struct Fx {
    Fx() : net(31), rogue(31, "rogue-release") { LM_CHECK_OK(sec::crypto_init()); }
    Bytes signed_by_fleet(const Spec &s) { return net.fleet.sign(envelope(net.fleet), view(manifest_data(s))); }
    Device device() const {
        Device d;
        d.soc = Soc::Esp32c3;
        d.board = ByteView{reinterpret_cast<const uint8_t *>("devkit"), 6};
        d.running_security = 5;
        d.storage_schema = 1;
        d.loader = 3;
        d.slot_bytes = 0x1d0000;
        return d;
    }
    Check check(const Bytes &cose, const State &st, Manifest &m, Sha256Digest &h) {
        return check_manifest(net.fleet.trust(), view(cose), device(), st, m, h);
    }
    fleet::Network net;
    fleet::Fleet rogue;
};

Bytes encoded(const State &s) {
    std::array<uint8_t, State::k_encoded_bytes> b{};
    std::size_t n = 0;
    LM_CHECK_OK(s.encode(MutByteView{b}, n));
    return Bytes(b.begin(), b.begin() + n);
}

} // namespace

LM_TEST("O02 a signed manifest for this SoC and board passes; nothing else does, and no state moves") {
    Fx fx;
    State st;
    const Bytes before = encoded(st);
    Manifest m;
    Sha256Digest h{};
    const Bytes good = fx.signed_by_fleet(Spec{});
    LM_CHECK(fx.check(good, st, m, h).status == Status::Ok);
    LM_CHECK(m.soc == Soc::Esp32c3 && m.image_bytes == 1'000'000 && m.security_version == 6);
    LM_CHECK_EQ(m.board_len, 6u);

    struct Case {
        const char *what;
        Spec spec;
        Status status;
        Reject why;
    };
    Spec other_soc;
    other_soc.soc = "esp32s3";
    Spec other_board;
    other_board.board = "otherboard";
    Spec too_big;
    too_big.image_bytes = 0x1d0000 + 4096; // bigger than the slot (and than the layout's maximum: refused as malformed)
    Spec exactly_fits;
    exactly_fits.image_bytes = 0x1d0000;
    Spec old_security;
    old_security.security = 4; // below what the device already runs (5)
    Spec equal_security;
    equal_security.security = 5;
    Spec schema_high;
    schema_high.schema_min = 2;
    schema_high.schema_max = 3;
    Spec loader_new;
    loader_new.loader_min = 4;
    Spec bad_block;
    bad_block.block = 8192;
    Spec bad_range;
    bad_range.schema_min = 3;
    bad_range.schema_max = 2;
    const Case cases[] = {
        {"another SoC", other_soc, Status::Unsupported, Reject::Soc},
        {"another board family", other_board, Status::Unsupported, Reject::Board},
        {"image larger than the slot", too_big, Status::BadFrame, Reject::Format},
        {"image exactly the slot", exactly_fits, Status::Ok, Reject::None},
        {"older security version", old_security, Status::AuthRejected, Reject::Downgrade},
        {"same security version", equal_security, Status::Ok, Reject::None},
        {"storage schema outside the image's range", schema_high, Status::Unsupported, Reject::Schema},
        {"loader newer than the device's", loader_new, Status::Unsupported, Reject::Loader},
        {"block size other than 4096", bad_block, Status::BadFrame, Reject::Format},
        {"schema range reversed", bad_range, Status::BadFrame, Reject::Format},
    };
    for (const Case &c : cases) {
        const Check r = fx.check(fx.signed_by_fleet(c.spec), st, m, h);
        if (r.status != c.status || r.why != c.why) {
            lmtest::fail(__FILE__, __LINE__, std::string(c.what) + ": got status " + std::to_string(static_cast<int>(r.status)) +
                                                 " reason " + std::to_string(static_cast<int>(r.why)));
        }
    }
    // The same manifest, but the device's layout has no second app slot: OTA_UNSUPPORTED, never squeezed in.
    Device d = fx.device();
    d.slot_bytes = 0;
    LM_CHECK(check_manifest(fx.net.fleet.trust(), view(good), d, st, m, h).why == Reject::NoSlot);
    // A slot smaller than the image (a layout that shrank): refused.
    d.slot_bytes = 500'000;
    LM_CHECK(check_manifest(fx.net.fleet.trust(), view(good), d, st, m, h).why == Reject::TooBig);
    LM_CHECK(encoded(st) == before); // a refusal leaves the rollback state (and so the boot target) as it was
}

LM_TEST("O02 tampering: every single-byte change of a signed manifest is refused; foreign, unsigned and mistyped ones too") {
    Fx fx;
    State st;
    Manifest m;
    Sha256Digest h{};
    const Bytes good = fx.signed_by_fleet(Spec{});
    LM_CHECK(fx.check(good, st, m, h).status == Status::Ok);
    std::size_t accepted = 0;
    for (std::size_t i = 0; i < good.size(); ++i) {
        Bytes bad = good;
        bad[i] ^= 0x01;
        const Check r = fx.check(bad, st, m, h);
        accepted += r.status == Status::Ok ? 1U : 0U;
    }
    LM_CHECK_EQ(accepted, 0u);
    // A truncated object and trailing bytes.
    LM_CHECK(fx.check(Bytes(good.begin(), good.end() - 1), st, m, h).status != Status::Ok);
    Bytes longer = good;
    longer.push_back(0);
    LM_CHECK(fx.check(longer, st, m, h).status != Status::Ok);
    // Signed by another fleet's key: the SDK trusts the one anchor it holds.
    const Bytes foreign = fx.rogue.sign(envelope(fx.rogue), view(manifest_data(Spec{})));
    LM_CHECK(fx.check(foreign, st, m, h).status == Status::AuthRejected);
    // The right body under another object type, and under a domain (a manifest is fleet-level).
    const Bytes mistyped = fx.net.fleet.sign(envelope(fx.net.fleet, 25), view(manifest_data(Spec{})));
    LM_CHECK(fx.check(mistyped, st, m, h).status != Status::Ok);
    member::Envelope in_domain = envelope(fx.net.fleet);
    in_domain.domain = fx.net.domain;
    LM_CHECK(fx.check(fx.net.fleet.sign(in_domain, view(manifest_data(Spec{}))), st, m, h).status ==
             Status::AuthRejected);
    // A bare manifest body with no signature is not a manifest.
    LM_CHECK(fx.check(manifest_data(Spec{}), st, m, h).status != Status::Ok);
    // The image hash inside the manifest is what the written image is compared with: a different hash is a different
    // manifest (a new signature is needed), never the same object.
    Spec other_hash;
    other_hash.sha_fill = 0x5A;
    Sha256Digest h2{};
    LM_CHECK(fx.check(fx.signed_by_fleet(other_hash), st, m, h2).status == Status::Ok);
    LM_CHECK(h2 != h);
}

LM_TEST("O02 rollback state: the only legal order, the migration lock, and the floor moves up only at confirm") {
    Fx fx;
    State st;
    Manifest m;
    Sha256Digest h{};
    LM_CHECK(fx.check(fx.signed_by_fleet(Spec{}), st, m, h).status == Status::Ok);
    LM_CHECK(st.migration_allowed());
    LM_CHECK(st.arm() == Status::Conflict);      // nothing is staged
    LM_CHECK(st.boot_new() == Status::Conflict);
    LM_CHECK(st.confirm() == Status::Conflict);
    LM_CHECK_OK(st.stage(m, h, 1));
    LM_CHECK(st.stage(m, h, 1) == Status::Busy); // one update at a time
    LM_CHECK(st.confirm() == Status::Conflict && st.boot_new() == Status::Conflict);
    LM_CHECK(st.migration_allowed() && st.floor() == 0);
    LM_CHECK_OK(st.arm());
    LM_CHECK(!st.migration_allowed());           // the rollback window is open from here on
    LM_CHECK(st.confirm() == Status::Conflict);
    LM_CHECK_OK(st.boot_new());
    LM_CHECK(st.phase() == Phase::Pending && !st.migration_allowed() && st.floor() == 0);
    LM_CHECK_OK(st.confirm());
    LM_CHECK(st.phase() == Phase::Idle && st.floor() == 6 && st.migration_allowed());
    // Now an image with the older security version is a downgrade, whatever its signature.
    Spec older;
    older.security = 5;
    LM_CHECK(fx.check(fx.signed_by_fleet(older), st, m, h).why == Reject::Downgrade);
    // A failed image is remembered by its hash: a re-signed manifest of it is not staged again, a new image is.
    State t;
    LM_CHECK_OK(t.stage(m, h, 0));
    t.abandon(true);
    LM_CHECK(t.phase() == Phase::Idle && t.floor() == 0 && t.has_failed());
    Sha256Digest hh{};
    Spec again; // the same image, signed again (ECDSA signatures differ, the image hash does not)
    LM_CHECK(fx.check(fx.signed_by_fleet(again), t, m, hh).why == Reject::Retry);
    Spec next;
    next.version = "1.2.1";
    next.security = 7;
    next.sha_fill = 0x5A; // a new image
    LM_CHECK(fx.check(fx.signed_by_fleet(next), t, m, hh).status == Status::Ok);
    LM_CHECK(t.stage(m, hh, 0) == Status::Ok);
    // The record codec accepts only what the transitions can write.
    Bytes enc = encoded(st);
    State back;
    LM_CHECK_OK(State::decode(view(enc), back));
    LM_CHECK(encoded(back) == enc);
    Bytes bad = enc;
    bad[1] = 4; // unknown phase
    LM_CHECK(State::decode(view(bad), back) == Status::BadFrame);
    bad = enc;
    bad[2] = 1; // Idle with a slot
    LM_CHECK(State::decode(view(bad), back) == Status::BadFrame);
    LM_CHECK(State::decode(ByteView{enc.data(), enc.size() - 1}, back) == Status::BadFrame);
}

LM_TEST("O03 sim: what the boot decision does in each state the record and the bootloader can leave behind") {
    Fx fx;
    Manifest m;
    Sha256Digest h{};
    LM_CHECK(fx.check(fx.signed_by_fleet(Spec{}), State{}, m, h).status == Status::Ok);
    State staged;
    LM_CHECK_OK(staged.stage(m, h, 1));
    State armed = staged;
    LM_CHECK_OK(armed.arm());
    State pending = armed;
    LM_CHECK_OK(pending.boot_new());
    const auto facts = [](uint8_t slot, bool pending_verify, bool invalid) {
        BootFacts f;
        f.running_slot = slot;
        f.running_pending_verify = pending_verify;
        f.running_marked_invalid = invalid;
        return f;
    };
    // slot 1 is the new image, slot 0 the old one
    LM_CHECK(on_boot(State{}, facts(0, false, false)) == BootAction::None);
    LM_CHECK(on_boot(staged, facts(0, false, false)) == BootAction::Restart);   // transfer was cut: start over
    LM_CHECK(on_boot(armed, facts(0, false, false)) == BootAction::Abandon);    // cut before the boot switch: old image
    LM_CHECK(on_boot(armed, facts(1, true, false)) == BootAction::SelfTest);    // switched, first boot of the new image
    LM_CHECK(on_boot(pending, facts(1, true, false)) == BootAction::SelfTest);  // crashed before the test finished, ran again
    LM_CHECK(on_boot(pending, facts(1, false, false)) == BootAction::Finalize); // marked valid, floor commit missing
    LM_CHECK(on_boot(pending, facts(0, false, false)) == BootAction::RolledBack); // the bootloader put the old image back
    LM_CHECK(on_boot(pending, facts(1, false, true)) == BootAction::RolledBack);  // running image marked invalid
    // Following each action ends in Idle with a floor that never went down, and never above the confirmed image.
    State s = pending;
    s.abandon(true); // RolledBack
    LM_CHECK(s.phase() == Phase::Idle && s.floor() == 0 && s.has_failed());
    s = pending;
    LM_CHECK_OK(s.confirm()); // SelfTest passed / Finalize
    LM_CHECK(s.phase() == Phase::Idle && s.floor() == 6);
}

namespace {

constexpr lm::sim::CutMode k_modes[3] = {lm::sim::CutMode::Before, lm::sim::CutMode::Torn, lm::sim::CutMode::After};

store::RecordJob &job() {
    static store::RecordJob j;
    return j;
}

Status commit(lm::sim::SimStore &s, const State &st) {
    store::RecordJob &j = job();
    j = store::RecordJob{};
    j.id = store::rec::ota_state;
    j.state = 1;
    std::size_t n = 0;
    LM_TRY(st.encode(MutByteView{j.payload.data(), j.payload.size()}, n));
    j.payload_len = static_cast<uint32_t>(n);
    return store::record_commit(s, j);
}

// Loads the record: NotFound (never committed) -> Idle default; anything unreadable is a failure of the test.
State load(lm::sim::SimStore &s, bool &found) {
    store::RecordJob &j = job();
    j = store::RecordJob{};
    j.id = store::rec::ota_state;
    const Status r = store::record_load(s, j);
    found = r == Status::Ok;
    State out;
    if (r == Status::Ok) {
        LM_CHECK_OK(State::decode(ByteView{j.payload.data(), j.payload_len}, out));
    } else {
        LM_CHECK(r == Status::NotFound);
    }
    return out;
}

} // namespace

LM_TEST("POWER-* OTA state (sim): a cut before/torn/after every Flash call of every state commit leaves the old or the new state, whole") {
    Fx fx;
    Manifest m;
    Sha256Digest h{};
    LM_CHECK(fx.check(fx.signed_by_fleet(Spec{}), State{}, m, h).status == Status::Ok);
    // The chain of states of a complete update, and the two ways back.
    std::vector<State> chain;
    chain.emplace_back(); // Idle, floor 0 (first commit: the record does not exist yet)
    State s = chain.back();
    LM_CHECK_OK(s.stage(m, h, 1));
    chain.push_back(s);
    LM_CHECK_OK(s.arm());
    chain.push_back(s);
    LM_CHECK_OK(s.boot_new());
    chain.push_back(s);
    LM_CHECK_OK(s.confirm());
    chain.push_back(s);
    State rolled = chain[3];
    rolled.abandon(true);
    chain.push_back(rolled); // index 5: Pending -> Idle by rollback (compared from chain[3])

    struct Step {
        std::size_t from, to;
    };
    const Step steps[] = {{0, 1}, {1, 2}, {2, 3}, {3, 4}, {3, 5}};
    std::size_t points = 0;
    for (const Step &st : steps) {
        // How many mutating calls does this commit make? Run it once without a cut.
        uint64_t ops = 0;
        {
            lm::sim::SimStore probe{lm::sim::StoreGeometry{}};
            for (std::size_t k = 0; k <= st.from; ++k) {
                LM_CHECK_OK(commit(probe, chain[k]));
            }
            const uint64_t b = probe.mutating_ops();
            LM_CHECK_OK(commit(probe, chain[st.to]));
            ops = probe.mutating_ops() - b;
        }
        LM_CHECK(ops >= 2); // record + marker: the commit is two Flash writes at least
        for (uint64_t k = 0; k < ops; ++k) {
            for (lm::sim::CutMode mode : k_modes) {
                lm::sim::SimStore store{lm::sim::StoreGeometry{}};
                for (std::size_t i = 0; i <= st.from; ++i) {
                    LM_CHECK_OK(commit(store, chain[i]));
                }
                store.arm_cut(store.mutating_ops() + k, mode);
                (void)commit(store, chain[st.to]);
                LM_CHECK(store.cut_fired());
                store.power_restore();
                bool found = false;
                const State got = load(store, found);
                const Bytes e = encoded(got);
                const bool old_state = e == encoded(chain[st.from]);
                const bool new_state = e == encoded(chain[st.to]);
                if (!old_state && !new_state) {
                    lmtest::fail(__FILE__, __LINE__, "step " + std::to_string(st.from) + "->" + std::to_string(st.to) + " cut " +
                                                         std::to_string(k) + ": neither the old nor the new state");
                }
                LM_CHECK(got.floor() >= chain[st.from].floor()); // the floor never goes down
                if (st.to != 4) {
                    LM_CHECK_EQ(got.floor(), chain[st.from].floor()); // and rises only with the confirm commit
                }
                ++points;
            }
        }
    }
    std::printf("  [measure] %zu cut points over 5 state commits (sim store)\n", points);
    LM_CHECK(points >= 5 * 2 * 3);
}

LM_TEST_MAIN()
