// meshsim commands of the USB serial slice. The root's serial port is the pty: bytes the Host
// writes reach RootUsb::on_bytes on the simulation thread, RootUsb writes answers straight back.
// RootUsb (src/serial) lives next to node 0 and is re-created after every reboot of that node; the
// sim keeps no protocol state of its own. Host kits are TEST-ONLY (fleet keys are public seeds).
#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cinttypes>
#include <cstdio>
#include <memory>

#include "control.hpp"
#include "core/member/records.hpp"
#include "core/wire/cbor.hpp"
#include "port/sim/sim_node.hpp"
#include "serial/pairing.hpp"
#include "serial/root_usb.hpp"

namespace meshsim {

namespace {

class PtyStream final : public lm::serial::ByteStream {
  public:
    explicit PtyStream(Sim &sim) : sim_(sim) {}
    std::size_t write(lm::ByteView out) override {
        const std::size_t n = sim_.pty != nullptr ? sim_.pty->write(out.data(), out.size()) : 0;
        sim_.world.node(0).serial.tx_bytes += n;
        return n;
    }

  private:
    Sim &sim_;
};

struct RootSide {
    std::unique_ptr<PtyStream> stream;
    std::unique_ptr<lm::serial::RootUsb> usb;
    uint32_t epoch = 0;
};

RootSide &side() {
    static RootSide s;
    return s;
}

constexpr uint32_t k_host_index_base = 2000;

lm::fleet::Kit host_kit(Sim &sim, uint32_t index) {
    return network(sim).fleet.device(k_host_index_base + index, "host-" + std::to_string(index));
}

} // namespace

// Attaches the adapter to node 0 whenever it has a live context it has not seen: after `boot 0`,
// `serial-reset` or the first command. A powered-off node drops the adapter (its RAM is gone).
void serial_sync(Sim &sim) {
    RootSide &s = side();
    if (sim.pty == nullptr) {
        return;
    }
    lm::sim::SimNode &n = sim.world.node(0);
    if (n.ctx() == nullptr) {
        s.usb.reset();
        s.stream.reset();
        return;
    }
    if (s.usb != nullptr && s.epoch == n.epoch()) {
        return;
    }
    s.usb.reset();
    s.stream = std::make_unique<PtyStream>(sim);
    s.epoch = n.epoch();
    // The gateway boot id is the node's power-cycle count (the persisted boot incarnation is not
    // exposed to the adapter yet): a reset always shows up as a new boot in HELLO.
    s.usb = std::make_unique<lm::serial::RootUsb>(n.ctx()->engine, *s.stream, uint64_t{n.epoch()} + 1);
    n.ctx()->engine.attach_serial(s.usb.get());
}

void serial_on_rx(Sim &sim, const uint8_t *data, std::size_t len) {
    serial_sync(sim);
    RootSide &s = side();
    if (s.usb == nullptr) {
        return;
    }
    lm::sim::SimNode &n = sim.world.node(0);
    s.usb->on_bytes(lm::ByteView{data, len}, n.clock.now());
    n.notify();
}

std::string cmd_serial_kit(Sim &sim, const Args &a) {
    uint64_t index = 0;
    if (a.size() < 2 || a.size() > 3 || (a.size() == 3 && !parse_u64(a[2], index)) || index > 1000) {
        return error("usage: serial-kit <path> [index 0..1000]");
    }
    const lm::fleet::Kit kit = host_kit(sim, static_cast<uint32_t>(index));
    lm::fleet::Network &net = network(sim);
    std::array<uint8_t, lm::store::k_max_payload> ident{};
    std::array<uint8_t, lm::store::k_max_payload> trust{};
    std::size_t ident_len = 0;
    std::size_t trust_len = 0;
    if (lm::member::encode_identity(lm::ByteView{kit.scalar}, lm::ByteView{kit.device_cose.data(), kit.device_cose.size()},
                                    lm::MutByteView{ident}, ident_len) != lm::Status::Ok ||
        lm::member::encode_trust(net.fleet.trust(), lm::MutByteView{trust}, trust_len) != lm::Status::Ok) {
        return error("kit encoding failed");
    }
    std::array<uint8_t, 1200> out{};
    lm::wire::CborWriter w{lm::MutByteView{out}};
    w.array(4);
    w.uint(1);
    w.bytes(lm::ByteView{ident.data(), ident_len});
    w.bytes(lm::ByteView{trust.data(), trust_len});
    w.bytes(net.domain.view());
    if (w.finish() != lm::Status::Ok) {
        return error("kit encoding failed");
    }
    const int fd = ::open(a[1].c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || ::write(fd, w.written().data(), w.size()) != static_cast<ssize_t>(w.size())) {
        if (fd >= 0) {
            ::close(fd);
        }
        return error("cannot write the kit file");
    }
    ::close(fd);
    return "{\"ok\":true,\"device\":\"" + std::string([&] {
               static const char *const k = "0123456789abcdef";
               std::string h;
               for (uint8_t b : kit.id.bytes) {
                   h += k[b >> 4U];
                   h += k[b & 15U];
               }
               return h;
           }()) + "\"}";
}

std::string cmd_serial_pair(Sim &sim, const Args &a) {
    uint16_t node = 0;
    uint64_t index = 0;
    if (a.size() < 2 || a.size() > 3 || !parse_node(sim, a[1], node) ||
        (a.size() == 3 && !parse_u64(a[2], index)) || index > 1000) {
        return error("usage: serial-pair <node> [index 0..1000]");
    }
    const lm::fleet::Kit kit = host_kit(sim, static_cast<uint32_t>(index));
    const lm::Status st = lm::serial::write_paired_host(sim.world.node(node).store, kit.id);
    if (st != lm::Status::Ok) {
        return error(std::string("pairing failed: ") + lm::status_name(st));
    }
    return "{\"ok\":true}";
}

std::string cmd_serial_status(Sim &sim, const Args &) {
    serial_sync(sim);
    RootSide &s = side();
    if (s.usb == nullptr) {
        return "{\"ok\":true,\"attached\":false}";
    }
    const lm::serial::UsbLink &l = s.usb->link();
    const lm::serial::UsbStats &st = l.stats();
    char buf[1100];
    std::snprintf(
        buf, sizeof buf,
        "{\"ok\":true,\"attached\":true,\"configured\":%s,\"paired\":%s,\"active\":%s,\"gen\":%u,\"session_id\":%u,"
        "\"rx_bytes\":%" PRIu64 ",\"rx_frames\":%" PRIu64 ",\"rx_cobs_bad\":%" PRIu64 ",\"rx_overflow\":%" PRIu64
        ",\"rx_bad_frame\":%" PRIu64 ",\"rx_unsupported\":%" PRIu64 ",\"rx_unknown_session\":%" PRIu64
        ",\"rx_auth_fail\":%" PRIu64 ",\"rx_replay\":%" PRIu64 ",\"rx_malformed\":%" PRIu64
        ",\"rx_credit_violation\":%" PRIu64 ",\"rx_hello\":%" PRIu64 ",\"rx_edhoc_dropped\":%" PRIu64
        ",\"tx_frames\":%" PRIu64 ",\"tx_partial\":%" PRIu64 ",\"tx_credit_blocked\":%" PRIu64
        ",\"hs_started\":%" PRIu64 ",\"hs_failed\":%" PRIu64 ",\"hs_rejected\":%" PRIu64
        ",\"sessions\":%" PRIu64 ",\"pings_rx\":%" PRIu64 ",\"unsupported_replies\":%" PRIu64
        ",\"replies_dropped\":%" PRIu64 ",\"last_failure\":\"%s\"}",
        l.configured() ? "true" : "false", s.usb->paired() ? "true" : "false", l.active() ? "true" : "false",
        l.session_gen(), l.session_id(), st.rx_bytes, st.rx_frames, st.rx_cobs_bad, st.rx_overflow,
        st.rx_bad_frame, st.rx_unsupported, st.rx_unknown_session, st.rx_auth_fail, st.rx_replay,
        st.rx_malformed, st.rx_credit_violation, st.rx_hello, st.rx_edhoc_dropped, st.tx_frames,
        st.tx_partial, st.tx_credit_blocked, st.hs_started, st.hs_failed, st.hs_rejected, st.sessions,
        st.pings_rx, s.usb->stats().unsupported_replies, s.usb->stats().replies_dropped,
        lm::status_name(l.last_failure()));
    return buf;
}

// USB detach/replug: the line goes down (the root drops its session and starts HELLO again) and
// whatever was in flight on the wire is gone.
std::string cmd_serial_drop(Sim &sim, const Args &) {
    serial_sync(sim);
    RootSide &s = side();
    if (s.usb == nullptr || sim.pty == nullptr) {
        return error("no serial adapter (node 0 not booted or --serial-pty missing)");
    }
    uint8_t scratch[512];
    while (sim.pty->read(scratch, sizeof scratch) > 0) {
    }
    lm::sim::SimNode &n = sim.world.node(0);
    s.usb->on_disconnect(n.clock.now());
    n.notify();
    return "{\"ok\":true}";
}

std::string cmd_serial_reset(Sim &sim, const Args &) {
    lm::sim::SimNode &n = sim.world.node(0);
    n.power_cut();
    const lm::Status b = n.boot();
    if (b != lm::Status::Ok) {
        return error(std::string("boot failed: ") + lm::status_name(b));
    }
    serial_sync(sim);
    const auto st = static_cast<lm::Status>(lm_start(n.ctx()));
    n.notify();
    return std::string("{\"ok\":") + (st == lm::Status::Ok ? "true" : "false") + ",\"status\":\"" +
           lm::status_name(st) + "\"}";
}

} // namespace meshsim
