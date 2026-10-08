// USB serial (S10): the real root adapter (Engine on sim ports, EDHOC jobs on the sim worker) wired
// back-to-back to the Host's native helper (same UsbLink in the Host role). Acceptance IDs follow
// docs/IMPLEMENTATION.md §11 (S10). Protocol bench only: no cable, no timing evidence.
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

#include "capi/context.hpp"
#include "core/member/records.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"
#include "security/identity.hpp"
#include "fleet.hpp"
#include "hostnative/host_usb.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"
#include "serial/cobs.hpp"
#include "serial/bridge.hpp"
#include "serial/pairing.hpp"
#include "serial/root_usb.hpp"

using namespace lm;
using namespace lm::sim;
using Bytes = std::vector<uint8_t>;

namespace {

class MemStream final : public serial::ByteStream {
  public:
    std::size_t write(ByteView out) override {
        if (stall) {
            return 0;
        }
        const std::size_t n = limit != 0 && out.size() > limit ? limit : out.size();
        data.insert(data.end(), out.begin(), out.begin() + static_cast<std::ptrdiff_t>(n));
        return n;
    }
    Bytes data;
    bool stall = false;
    std::size_t limit = 0; // partial writes when non-zero
};

Bytes kit_bytes(fleet::Network &net, uint32_t index) {
    const fleet::Kit kit = net.fleet.device(2000 + index, "host-" + std::to_string(index));
    std::array<uint8_t, store::k_max_payload> ident{};
    std::array<uint8_t, store::k_max_payload> trust{};
    std::size_t il = 0;
    std::size_t tl = 0;
    LM_CHECK_OK(member::encode_identity(ByteView{kit.scalar}, ByteView{kit.device_cose.data(), kit.device_cose.size()},
                                        MutByteView{ident}, il));
    LM_CHECK_OK(member::encode_trust(net.fleet.trust(), MutByteView{trust}, tl));
    Bytes out(1200);
    wire::CborWriter w{MutByteView{out.data(), out.size()}};
    w.array(4);
    w.uint(1);
    w.bytes(ByteView{ident.data(), il});
    w.bytes(ByteView{trust.data(), tl});
    w.bytes(net.domain.view());
    LM_CHECK_OK(w.finish());
    out.resize(w.size());
    return out;
}

struct Rig {
    // root_net: the fleet the root belongs to. host_net: the fleet the Host kit comes from.
    Rig(uint64_t seed, fleet::Network *host_net_override = nullptr, uint32_t paired_index = 0,
        uint32_t host_index = 0, bool pair = true)
        : net(seed), world(WorldOptions{seed, 0}) {
        NodeOptions o;
        o.role = Role::Root;
        (void)world.add_node(o);
        fleet::Network &hn = host_net_override != nullptr ? *host_net_override : net;
        root_kit = net.make_root();
        LM_CHECK_OK(fleet::provision(node().store, net, root_kit));
        if (pair) {
            const fleet::Kit p = net.fleet.device(2000 + paired_index, "host-" + std::to_string(paired_index));
            LM_CHECK_OK(serial::write_paired_host(node().store, p.id));
        }
        boot();
        host = std::make_unique<hostnative::HostUsb>(1);
        const Bytes kb = kit_bytes(hn, host_index);
        host_status = host->load_kit(ByteView{kb.data(), kb.size()});
        if (host_status == Status::Ok) {
            host->open(hnow());
        }
    }

    SimNode &node() { return world.node(0); }
    Engine &eng() { return node().ctx()->engine; }
    MonoTime hnow() const { return MonoTime{world.now_us()}; }
    void boot() {
        LM_CHECK_OK(node().boot());
        root_out.data.clear();
        root = std::make_unique<serial::RootUsb>(eng(), root_out, uint64_t{node().epoch()} + 1);
        eng().attach_serial(root.get());
        LM_CHECK_EQ(lm_start(node().ctx()), LM_STATUS_OK);
    }
    void reset_root() {
        node().power_cut();
        node().store.power_restore();
        root.reset();
        boot();
    }
    // One millisecond of virtual time: root runs, bytes cross both ways, Host ticks.
    void step() {
        world.run_until(world.now_us() + 1000);
        if (!root_out.data.empty() && host_status == Status::Ok) {
            Bytes b;
            b.swap(root_out.data);
            wire_log.insert(wire_log.end(), b.begin(), b.end());
            host->feed(ByteView{b.data(), b.size()}, hnow());
        }
        if (host_status == Status::Ok) {
            if (host->deadline() <= hnow()) {
                host->tick(hnow());
            }
            std::array<uint8_t, 4096> buf{};
            for (std::size_t n; (n = host->take_tx(MutByteView{buf})) > 0;) {
                to_root(ByteView{buf.data(), n});
            }
        }
        drain_events();
    }
    void to_root(ByteView b) {
        if (root != nullptr && node().ctx() != nullptr) {
            root->on_bytes(b, node().clock.now());
            node().notify();
        }
    }
    void drain_events() {
        hostnative::HostEvent e;
        while (host->next_event(e, hnow())) {
            if (e.kind == hostnative::HostEvent::Kind::Record && e.aux == 4) {
                ++responses;
                last_response = e.payload;
                lane1_peak = std::max<uint64_t>(lane1_peak, host->link().rx_outstanding_frames(1));
            }
            if (e.kind == hostnative::HostEvent::Kind::SessionDown) {
                ++host_downs;
            }
        }
    }
    template <class P> bool until(P pred, uint64_t max_ms) {
        for (uint64_t t = 0; t < max_ms && !pred(); ++t) {
            step();
        }
        return pred();
    }
    bool both_active() { return root->link().active() && host->link().active(); }

    fleet::Network net;
    World world;
    fleet::NodeKit root_kit;
    MemStream root_out;
    std::unique_ptr<serial::RootUsb> root;
    std::unique_ptr<hostnative::HostUsb> host;
    Status host_status = Status::Ok;
    Bytes wire_log; // everything the root wrote (attacker capture)
    uint64_t responses = 0;
    uint64_t host_downs = 0;
    uint64_t lane1_peak = 0;
    Bytes last_response;
};

Bytes request(uint8_t seed, uint8_t method, std::size_t param_bytes) {
    Bytes out(param_bytes + 64);
    wire::CborWriter w{MutByteView{out.data(), out.size()}};
    w.array(3);
    std::array<uint8_t, 16> id{};
    id.fill(seed);
    w.bytes(ByteView{id});
    w.uint(method);
    Bytes params(param_bytes, seed);
    w.bytes(ByteView{params.data(), params.size()});
    LM_CHECK_OK(w.finish());
    out.resize(w.size());
    return out;
}

} // namespace

LM_TEST("ISSUE19-3 serial: real diagnostics carry recovery through the encrypted USB link") {
    Rig r(19);
    serial::Bridge bridge{r.eng(), *r.root, 19};
    LM_CHECK(r.until([&] { return r.both_active(); }, 3000));
    auto &facts = r.node().health.extra;
    facts.radio_recovery_valid = true;
    facts.radio_recovery_reason = 256;
    facts.radio_recovery_attempts = 2;
    std::array<uint8_t, 32> req{};
    wire::CborWriter w{MutByteView{req}};
    w.array(3);
    std::array<uint8_t, 16> id{};
    w.bytes(ByteView{id});
    w.uint(16); // DIAGNOSTICS
    w.null();
    LM_CHECK_OK(w.finish());
    LM_CHECK_OK(r.host->send(gen::SerialKind::Request, r.host->link().session_gen(), ByteView{req.data(), w.size()}, r.hnow()));
    LM_CHECK(r.until([&] { return r.responses == 1; }, 2000));
    wire::CborReader response{ByteView{r.last_response.data(), r.last_response.size()}};
    (void)response.array(4, 4);
    (void)response.bstr(16, 16);
    LM_CHECK_EQ(response.uint_in(0, 100), static_cast<uint64_t>(Status::Ok));
    LM_CHECK(response.try_null());
    wire::CborReader result{response.bstr(1, 8192)};
    LM_CHECK_OK(response.finish());
    wire::CborReader::Item map;
    LM_CHECK(result.next(map) && map.type == wire::CborType::Map);
    bool recovery = false;
    for (uint64_t i = 0; i < map.arg; ++i) {
        const ByteView key = result.tstr(1, 64);
        const ByteView value = result.skip_item();
        if (std::string(reinterpret_cast<const char *>(key.data()), key.size()) != "driver") continue;
        wire::CborReader driver{value};
        wire::CborReader::Item fields;
        LM_CHECK(driver.next(fields) && fields.type == wire::CborType::Map);
        for (uint64_t j = 0; j < fields.arg; ++j) {
            const ByteView name = driver.tstr(1, 64);
            const std::string text(reinterpret_cast<const char *>(name.data()), name.size());
            const uint64_t number = driver.uint_in(0, UINT64_MAX);
            if (text == "radio_recovery_attempts") recovery = number == 2;
        }
        LM_CHECK_OK(driver.finish());
    }
    LM_CHECK_OK(result.finish());
    LM_CHECK(recovery);
}

LM_TEST("S09-sim COBS round trip, resync and cap") {
    Bytes buf(serial::k_cobs_headroom + 600);
    for (std::size_t n : {std::size_t{1}, std::size_t{2}, std::size_t{253}, std::size_t{254}, std::size_t{255},
                          std::size_t{508}, std::size_t{509}}) {
        for (int fill : {0, 7}) {
            Bytes data(n, static_cast<uint8_t>(fill));
            if (n > 3) {
                data[n / 2] = 0;
            }
            std::memcpy(buf.data() + serial::k_cobs_headroom, data.data(), n);
            const std::size_t enc = serial::cobs_encode_in_place(MutByteView{buf.data(), buf.size()}, serial::k_cobs_headroom, n);
            LM_CHECK(enc > n);
            LM_CHECK_EQ(buf[enc - 1], 0);
            for (std::size_t i = 0; i + 1 < enc; ++i) {
                LM_CHECK(buf[i] != 0);
            }
            Bytes out(1024);
            serial::CobsDecoder dec{MutByteView{out.data(), out.size()}};
            int frames = 0;
            for (std::size_t i = 0; i < enc; ++i) {
                if (dec.push(buf[i]) == serial::CobsDecoder::Result::Frame) {
                    ++frames;
                    LM_CHECK(bytes_equal(dec.frame(), ByteView{data.data(), data.size()}));
                }
            }
            LM_CHECK_EQ(frames, 1);
        }
    }
    // Noise, then a valid frame: the decoder resynchronises at the delimiter.
    Bytes out(64);
    serial::CobsDecoder dec{MutByteView{out.data(), out.size()}};
    const uint8_t noise[] = {0x09, 1, 2, 0, 0, 0x03, 5, 0};
    int frames = 0;
    for (uint8_t b : noise) {
        frames += dec.push(b) == serial::CobsDecoder::Result::Frame ? 1 : 0;
    }
    LM_CHECK_EQ(frames, 0);
    LM_CHECK_EQ(dec.bad_frames(), 2u); // two truncated blocks; idle delimiters are not errors
    // Overflow: 100 bytes into a 64-byte buffer are discarded up to the delimiter, the next frame is fine.
    for (int i = 0; i < 100; ++i) {
        (void)dec.push(0x7E);
    }
    LM_CHECK(dec.push(0) == serial::CobsDecoder::Result::Bad);
    LM_CHECK_EQ(dec.overflows(), 1u);
    (void)dec.push(0x03);
    (void)dec.push(0x11);
    (void)dec.push(0x22);
    LM_CHECK(dec.push(0) == serial::CobsDecoder::Result::Frame);
    LM_CHECK_EQ(dec.frame().size(), 2u);
}

LM_TEST("S09-sim HELLO -> EDHOC purpose 3 -> ACTIVE, PING keeps it, session ids and credits") {
    Rig r(21);
    LM_CHECK_OK(r.host_status);
    LM_CHECK(r.until([&] { return r.both_active(); }, 3000));
    LM_CHECK_EQ(r.root->link().session_gen(), 1u);
    LM_CHECK_EQ(r.host->link().session_gen(), 1u);
    LM_CHECK_EQ(r.root->link().session_id(), r.host->link().session_id());
    LM_CHECK(r.root->link().session_id() != 0);
    LM_CHECK(r.root->paired());
    LM_CHECK(r.root->link().peer_device() == r.net.fleet.device(2000, "host-0").id);
    LM_CHECK(r.host->link().peer_device() == r.root_kit.kit.id);
    // Both sides granted the initial windows: 16/32 KiB data, 2/2 KiB control.
    r.step();
    r.step();
    LM_CHECK_EQ(r.host->link().tx_available_frames(0), 16u);
    LM_CHECK_EQ(r.host->link().tx_available_frames(1), 2u);
    LM_CHECK_EQ(r.root->link().tx_available_frames(0), 16u);
    // 40 s of quiet: PING every 5 s in each direction, nobody times out (silence limit 15 s).
    for (int i = 0; i < 40000; ++i) {
        r.step();
    }
    LM_CHECK(r.both_active());
    LM_CHECK_EQ(r.root->link().session_gen(), 1u);
    LM_CHECK(r.root->link().stats().pings_rx >= 6);
    LM_CHECK(r.host->link().stats().pings_rx >= 6);
    LM_CHECK_EQ(r.root->link().stats().rx_auth_fail, 0u);
    LM_CHECK_EQ(r.host->link().stats().rx_auth_fail, 0u);
}

LM_TEST("S09-sim credits: data window 16, reserved control lane, no double count") {
    Rig r(22);
    LM_CHECK(r.until([&] { return r.both_active(); }, 3000));
    r.step();
    r.step();
    const uint32_t gen = r.host->link().session_gen();
    for (uint8_t i = 0; i < 16; ++i) {
        const Bytes q = request(static_cast<uint8_t>(i + 1), 1, 200);
        LM_CHECK_OK(r.host->send(gen::SerialKind::Request, gen, ByteView{q.data(), q.size()}, r.hnow()));
    }
    // The 17th has no credit: local flow control (Busy), nothing goes out.
    const Bytes extra = request(99, 2, 200);
    LM_CHECK(r.host->send(gen::SerialKind::Request, gen, ByteView{extra.data(), extra.size()}, r.hnow()) ==
             Status::Busy);
    LM_CHECK_EQ(r.host->link().stats().tx_credit_blocked, 1u);
    LM_CHECK_EQ(r.host->link().tx_available_frames(0), 0u);
    // The root answers all 16 through the control lane (window 2 at a time) and returns the credit.
    LM_CHECK(r.until([&] { return r.responses == 16; }, 3000));
    LM_CHECK(r.lane1_peak <= 2);
    LM_CHECK_EQ(r.root->stats().unsupported_replies, 16u);
    LM_CHECK_EQ(r.root->link().stats().rx_credit_violation, 0u);
    LM_CHECK(r.until([&] { return r.host->link().tx_available_frames(0) > 0; }, 500));
    LM_CHECK_OK(r.host->send(gen::SerialKind::Request, gen, ByteView{extra.data(), extra.size()}, r.hnow()));
    LM_CHECK(r.until([&] { return r.responses == 17; }, 500));
    // The response body is [request_id, UNSUPPORTED, null, null]: nothing is faked.
    wire::CborReader rd{ByteView{r.last_response.data(), r.last_response.size()}};
    (void)rd.array(4, 4);
    LM_CHECK_EQ(rd.bstr(16, 16).size(), 16u);
    LM_CHECK_EQ(rd.uint_in(0, 100), static_cast<uint64_t>(Status::Unsupported));
    LM_CHECK(rd.try_null());
    LM_CHECK(rd.try_null());
    LM_CHECK_OK(rd.finish());
}

LM_TEST("S09-sim 8230 B frame accepted, 8193 B payload refused, corruption and noise resync") {
    Rig r(23);
    LM_CHECK(r.until([&] { return r.both_active(); }, 3000));
    r.step();
    r.step();
    const uint32_t gen = r.host->link().session_gen();
    // Largest legal REQUEST: 8192 B of deterministic CBOR -> decoded 18 + 8192 + 16 + 4 = 8230.
    const Bytes big = request(5, 3, 8192 - 22);
    LM_CHECK_EQ(big.size(), 8192u);
    LM_CHECK_OK(r.host->send(gen::SerialKind::Request, gen, ByteView{big.data(), big.size()}, r.hnow()));
    LM_CHECK(r.until([&] { return r.responses == 1; }, 2000));
    const Bytes huge(8193, 0);
    LM_CHECK(r.host->send(gen::SerialKind::Request, gen, ByteView{huge.data(), huge.size()}, r.hnow()) ==
             Status::PayloadTooLarge);

    // A bit flipped inside a record: CRC error, dropped, the stream resynchronises at the delimiter.
    const uint64_t bad0 = r.root->link().stats().rx_bad_frame;
    const Bytes q1 = request(6, 1, 100);
    LM_CHECK_OK(r.host->send(gen::SerialKind::Request, gen, ByteView{q1.data(), q1.size()}, r.hnow()));
    std::array<uint8_t, 2048> buf{};
    const std::size_t n = r.host->take_tx(MutByteView{buf});
    LM_CHECK(n > 60);
    buf[n / 2] = buf[n / 2] == 0x55 ? 0x56 : 0x55; // stays non-zero: the frame boundary survives
    r.to_root(ByteView{buf.data(), n});
    r.step();
    LM_CHECK_EQ(r.root->link().stats().rx_bad_frame, bad0 + 1);
    LM_CHECK_EQ(r.responses, 1u); // the corrupted request was NOT applied

    // 10 000 bytes without a delimiter: discarded, counted once, then a valid record still works.
    Bytes noise(10000, 0x55);
    noise.push_back(0);
    r.to_root(ByteView{noise.data(), noise.size()});
    const Bytes q2 = request(7, 1, 100);
    LM_CHECK_OK(r.host->send(gen::SerialKind::Request, gen, ByteView{q2.data(), q2.size()}, r.hnow()));
    // FIX11-D5 (docs/19 §5): the record after the dropped one carries a counter gap. It is NOT applied and the session is
    // cut (its credits and any acknowledgement built on the lost record cannot be trusted); a fresh EDHOC follows.
    LM_CHECK(r.until([&] { return r.root->link().stats().rx_counter_gap == 1; }, 2000));
    LM_CHECK(r.root->link().stats().rx_overflow >= 1);
    LM_CHECK_EQ(r.responses, 1u);
    LM_CHECK(r.until([&] { return r.both_active() && r.host->link().session_gen() > gen; }, 8000));
    LM_CHECK_EQ(r.root->link().stats().rx_auth_fail, 0u);
    const uint32_t gen2 = r.host->link().session_gen();
    const Bytes q3 = request(8, 1, 100);
    LM_CHECK_OK(r.host->send(gen::SerialKind::Request, gen2, ByteView{q3.data(), q3.size()}, r.hnow()));
    LM_CHECK(r.until([&] { return r.responses == 2; }, 2000));
}

LM_TEST("H03-sim reset and replug: old session results are never applied") {
    Rig r(24);
    LM_CHECK(r.until([&] { return r.both_active(); }, 3000));
    r.step();
    r.step();
    const uint32_t gen1 = r.host->link().session_gen();
    const uint32_t sid1 = r.host->link().session_id();
    const Bytes q = request(1, 1, 50);
    LM_CHECK_OK(r.host->send(gen::SerialKind::Request, gen1, ByteView{q.data(), q.size()}, r.hnow()));
    // Capture what the Host sent in session 1 (attacker/stale replay material).
    std::array<uint8_t, 2048> buf{};
    const std::size_t old_n = r.host->take_tx(MutByteView{buf});
    const Bytes old_host_bytes(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(old_n));
    r.to_root(ByteView{buf.data(), old_n});
    LM_CHECK(r.until([&] { return r.responses == 1; }, 1000));
    const Bytes old_root_bytes = r.wire_log; // includes a session-1 RESPONSE

    // The root MCU resets: RAM gone, fresh boot id. The Host learns from HELLO and re-handshakes.
    r.reset_root();
    LM_CHECK(r.until([&] { return r.root->link().active() && r.host->link().session_gen() == 2 &&
                                  r.host->link().active(); }, 8000));
    LM_CHECK(r.host->link().session_id() != sid1);
    LM_CHECK(r.host_downs >= 1); // the old session ended (Replaced) before/as the new one began
    // A result for session 1 cannot be sent into session 2.
    LM_CHECK(r.host->send(gen::SerialKind::Request, gen1, ByteView{q.data(), q.size()}, r.hnow()) ==
             Status::Conflict);
    // Replay of session-1 traffic in both directions: unknown session, applied to nothing.
    const uint64_t unk_root = r.root->link().stats().rx_unknown_session;
    const uint64_t unk_host = r.host->link().stats().rx_unknown_session;
    const uint64_t resp = r.responses;
    r.to_root(ByteView{old_host_bytes.data(), old_host_bytes.size()});
    r.host->feed(ByteView{old_root_bytes.data(), old_root_bytes.size()}, r.hnow());
    r.drain_events();
    LM_CHECK(r.root->link().stats().rx_unknown_session > unk_root);
    LM_CHECK(r.host->link().stats().rx_unknown_session > unk_host);
    LM_CHECK_EQ(r.responses, resp);
    LM_CHECK_EQ(r.root->stats().unsupported_replies, 0u); // the reset root never saw the old request

    // Replug: the root loses the line, drops its session, says HELLO; a new session follows.
    const uint32_t gen2 = r.host->link().session_gen();
    r.root->on_disconnect(r.node().clock.now());
    LM_CHECK(!r.root->link().active());
    LM_CHECK(r.until([&] { return r.root->link().active() && r.host->link().session_gen() == gen2 + 1; }, 8000));
    LM_CHECK(r.until([&] { return r.both_active(); }, 500));
}

namespace {

// A scripted root the test controls: it accepts the legitimate Host (trust anchor and pairing of the
// real fleet) but presents whatever credential chain the test gives it. Same UsbLink, root role.
struct FakeRoot final : serial::UsbEnv {
    FakeRoot(const fleet::Kit &self_kit, ByteView delegation, const member::TrustAnchor &accepts,
             const DeviceId &paired, const DomainId &domain)
        : link(serial::UsbRole::Root, *this, nullptr, 7, false) {
        LM_CHECK_OK(sec::crypto_init());
        LM_CHECK_OK(sec::import_signing_key(ByteView{self_kit.scalar}, key));
        std::size_t ccs_len = 0;
        LM_CHECK_OK(sec::ccs_encode(ByteView{self_kit.dc.serial.data(), self_kit.dc.serial_len}, self_kit.pub,
                                    MutByteView{ccs}, ccs_len));
        serial::UsbKit k;
        k.key = key;
        k.ccs = ByteView{ccs.data(), ccs_len};
        k.device_cose = ByteView{self_kit.device_cose.data(), self_kit.device_cose.size()};
        k.delegation_cose = delegation;
        k.trust = accepts;
        k.self = self_kit.id;
        k.domain = domain;
        k.paired = paired;
        LM_CHECK_OK(link.configure(k));
    }
    ~FakeRoot() { sec::destroy_key(key); }
    std::size_t write(ByteView b) override {
        out.insert(out.end(), b.begin(), b.end());
        return b.size();
    }
    void random(MutByteView o) override {
        for (uint8_t &b : o) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            b = static_cast<uint8_t>(seed >> 56U);
        }
    }
    sec::HandshakeSlot hs;
    sec::HandshakeSlot *slot_acquire() override { return &hs; }
    void slot_release() override {}
    Status submit(Handle s, JobClass, port::JobFn f, void *a) override {
        slot = s;
        fn = f;
        arg = a;
        have = true;
        return Status::Ok;
    }
    void run_jobs(MonoTime now) {
        for (int i = 0; i < 8 && have; ++i) {
            have = false;
            port::JobEnv env{store};
            const Status st = fn(env, arg);
            link.on_job_done(slot, st, now);
        }
    }
    struct NoStore final : port::Store {
        Status slot_read(uint16_t, uint8_t, MutByteView, std::size_t &) override { return Status::StorageFailure; }
        Status slot_write(uint16_t, uint8_t, ByteView) override { return Status::StorageFailure; }
        Status slot_erase(uint16_t, uint8_t) override { return Status::StorageFailure; }
        uint32_t journal_segment_bytes() const override { return 0; }
        uint32_t journal_segments() const override { return 0; }
        Status journal_read(uint32_t, MutByteView) override { return Status::StorageFailure; }
        Status journal_write(uint32_t, ByteView) override { return Status::StorageFailure; }
        Status journal_erase(uint32_t) override { return Status::StorageFailure; }
    } store;
    serial::UsbLink link;
    sec::KeyHandle key;
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs{};
    Bytes out;
    Handle slot;
    port::JobFn fn = nullptr;
    void *arg = nullptr;
    bool have = false;
    uint64_t seed = 12345;
};

// Runs Host <-> FakeRoot for `ms` milliseconds of virtual time.
void pump_pair(hostnative::HostUsb &host, FakeRoot &root, uint64_t &t_us, uint64_t ms) {
    for (uint64_t i = 0; i < ms; ++i) {
        t_us += 1000;
        const MonoTime now{t_us};
        if (root.link.deadline() <= now) {
            root.link.on_timer(now);
        }
        root.run_jobs(now);
        if (!root.out.empty()) {
            Bytes b;
            b.swap(root.out);
            host.feed(ByteView{b.data(), b.size()}, now);
        }
        if (host.deadline() <= now) {
            host.tick(now);
        }
        std::array<uint8_t, 4096> buf{};
        for (std::size_t n; (n = host.take_tx(MutByteView{buf})) > 0;) {
            root.link.on_bytes(ByteView{buf.data(), n}, now);
            root.run_jobs(now);
        }
        hostnative::HostEvent e;
        while (host.next_event(e, now)) {
        }
    }
}

} // namespace

LM_TEST("S09-sim fake root is refused by the Host (foreign fleet, foreign domain) and a control run connects") {
    fleet::Network real(40);
    fleet::Network rogue(41, "rogue");
    const Bytes kit = kit_bytes(real, 0);
    const fleet::Kit host_kit = real.fleet.device(2000, "host-0");

    struct Case {
        const char *name;
        fleet::Kit root;
        Bytes delegation;
        bool expect_active;
        Status failure;
    };
    // (a) a root of another fleet: its DeviceCredential is not signed by our fleet.
    // (b) our fleet's root, but the delegation names another domain than the Host expects.
    // (c) control: the genuine chain connects, so (a)/(b) fail because of the chain, not the rig.
    DomainId other_domain;
    other_domain.bytes.fill(0x77);
    const Case cases[] = {
        {"foreign fleet", rogue.root, rogue.delegation_cose, false, Status::AuthRejected},
        {"foreign domain", real.root, real.fleet.delegation(real.root, other_domain), false, Status::NetworkMismatch},
        {"genuine", real.root, real.delegation_cose, true, Status::Ok},
    };
    for (const Case &c : cases) {
        FakeRoot root(c.root, ByteView{c.delegation.data(), c.delegation.size()}, real.fleet.trust(),
                      host_kit.id, real.domain);
        hostnative::HostUsb host(1);
        LM_CHECK_OK(host.load_kit(ByteView{kit.data(), kit.size()}));
        uint64_t t = 1000000;
        host.open(MonoTime{t});
        root.link.open(MonoTime{t});
        pump_pair(host, root, t, 6000);
        if (c.expect_active) {
            LM_CHECK(host.link().active() && root.link.active());
            LM_CHECK_EQ(host.link().stats().hs_rejected, 0u);
        } else {
            LM_CHECK(!host.link().active());
            LM_CHECK(!root.link.active()); // no key confirmation without the Host's PING
            LM_CHECK(host.link().stats().hs_rejected >= 1);
            LM_CHECK(host.link().last_failure() == c.failure);
            std::printf("    %s: Host refused with %s\n", c.name, status_name(host.link().last_failure()));
        }
    }
}

LM_TEST("S09-sim fake host is refused by the root (unpaired, foreign fleet, no pairing record)") {
    struct Case {
        const char *name;
        uint32_t paired_index;
        uint32_t host_index;
        bool foreign_fleet;
        bool pair;
        bool expect_active;
    };
    fleet::Network foreign(52, "foreign");
    const Case cases[] = {
        {"valid fleet device, not the paired Host", 0, 1, false, true, false},
        {"other fleet", 0, 0, true, true, false},
        {"no pairing record", 0, 0, false, false, false},
        {"control: the paired Host", 0, 0, false, true, true},
    };
    for (const Case &c : cases) {
        Rig r(51, c.foreign_fleet ? &foreign : nullptr, c.paired_index, c.host_index, c.pair);
        LM_CHECK_OK(r.host_status);
        r.until([&] { return r.both_active(); }, 9000);
        LM_CHECK_EQ(r.both_active(), c.expect_active);
        if (!c.expect_active) {
            LM_CHECK(!r.root->link().active() && !r.host->link().active());
            LM_CHECK(r.root->link().stats().hs_rejected >= 1);
            LM_CHECK_EQ(r.root->link().stats().sessions, 0u);
            LM_CHECK_EQ(r.root->stats().unsupported_replies, 0u);
            std::printf("    %s: root %s\n", c.name, status_name(r.root->link().last_failure()));
        }
    }
}

LM_TEST("S13-D10 sim: the USB handshake waits for the node's exchange slot, takes it next and gives it back") {
    {
        Rig r(60);
        link::Exchange &x = r.eng().link().exchange();
        LM_CHECK(!x.lend_scratch().empty()); // a join module holds the node's one handshake slot
        LM_CHECK(!r.until([&] { return r.root->link().active(); }, 2500)); // credentials verified, waiting
        LM_CHECK(x.busy());
        x.return_scratch();
        LM_CHECK(r.until([&] { return r.both_active(); }, 3000));
        LM_CHECK(!x.busy() && !x.job_pending()); // the slot is back with the exchange
        LM_CHECK_EQ(r.root->link().stats().hs_failed, uint64_t{0});
    }
    {
        Rig r(61);
        link::Exchange &x = r.eng().link().exchange();
        LM_CHECK(!x.lend_scratch().empty());
        // Held longer than the 4 s attempt: it fails (Expired) while the slot is still taken.
        LM_CHECK(r.until([&] { return r.root->link().stats().hs_failed >= 1; }, 8000));
        LM_CHECK(!r.root->link().active());
        r.host->close(); // no second attempt (which would queue for the slot again) while we look
        LM_CHECK(!r.until([&] { return r.root->link().active(); }, 50));
        x.return_scratch();
        LM_CHECK(!x.busy()); // the failed attempt left no reservation behind
        r.host->open(r.hnow());
        LM_CHECK(r.until([&] { return r.both_active(); }, 40000)); // the Host retries and gets the slot
        LM_CHECK(!x.busy() && !x.job_pending());
    }
}

// ARCH2-P2B: the link views the kit's CCS and credentials instead of copying them. configure() still refuses exactly
// what the copy refused (a CCS over k_ccs_max_bytes, a root without delegation, a credential object CBOR
// [device] / [device, delegation] over k_cred_bytes), and the Host adapter takes one kit (the storage the link views).
LM_TEST("S09-sim configure keeps the kit limits with views; the Host adapter loads one kit") {
    struct IdleEnv final : serial::UsbEnv {
        std::size_t write(ByteView b) override { return b.size(); }
        void random(MutByteView o) override { std::fill(o.begin(), o.end(), uint8_t{1}); }
        Status submit(Handle, JobClass, port::JobFn, void *) override { return Status::Busy; }
        sec::HandshakeSlot *slot_acquire() override { return nullptr; }
        void slot_release() override {}
    } env;
    constexpr std::size_t cap = serial::UsbLink::k_cred_bytes;
    const Bytes ccs(sec::k_ccs_max_bytes + 1, 0xA0);
    const Bytes dc(300, 0xA1);
    const Bytes deleg(cap - 1 - 3 - dc.size() - 3, 0xA2); // 1 + (3 + 300) + (3 + 653) = cap
    const Bytes deleg_over(deleg.size() + 1, 0xA2);
    serial::UsbKit k;
    k.ccs = ByteView{ccs.data(), ccs.size()};
    k.device_cose = ByteView{dc.data(), dc.size()};
    k.delegation_cose = ByteView{deleg.data(), deleg.size()};

    serial::UsbLink root(serial::UsbRole::Root, env, nullptr, 1, false);
    LM_CHECK_EQ(root.configure(k), Status::NoCapacity); // CCS one byte over
    k.ccs = ByteView{ccs.data(), sec::k_ccs_max_bytes};
    k.delegation_cose = ByteView{};
    LM_CHECK_EQ(root.configure(k), Status::InvalidArgument);
    k.delegation_cose = ByteView{deleg_over.data(), deleg_over.size()};
    LM_CHECK_EQ(root.configure(k), Status::NoCapacity);
    LM_CHECK(!root.configured());
    k.delegation_cose = ByteView{deleg.data(), deleg.size()};
    LM_CHECK_OK(root.configure(k));
    LM_CHECK(root.configured());

    serial::UsbLink host(serial::UsbRole::Host, env, nullptr, 1, false);
    const Bytes big(cap - 1 - 3 + 1, 0xA3); // [device] alone, one byte over
    k.device_cose = ByteView{big.data(), big.size()};
    LM_CHECK_EQ(host.configure(k), Status::NoCapacity);
    k.device_cose = ByteView{big.data(), big.size() - 1};
    LM_CHECK_OK(host.configure(k)); // a Host's object has no delegation (the kit's one is ignored)

    fleet::Network net(42);
    const Bytes kb = kit_bytes(net, 0);
    hostnative::HostUsb h(1);
    LM_CHECK_OK(h.load_kit(ByteView{kb.data(), kb.size()}));
    LM_CHECK_EQ(h.load_kit(ByteView{kb.data(), kb.size()}), Status::Busy);
    LM_CHECK(h.link().configured());
}

LM_TEST_MAIN()
