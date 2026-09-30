#include "hostnative/lmh_api.h"

#include <new>

#include "hostnative/host_usb.hpp"

using lm::hostnative::HostEvent;
using lm::hostnative::HostUsb;

struct lmh_usb {
    HostUsb usb;
    explicit lmh_usb(uint64_t boot) : usb(boot) {}
};

namespace {

constexpr int32_t s(lm::Status st) { return static_cast<int32_t>(st); }
lm::MonoTime t(uint64_t us) { return lm::MonoTime{us}; }

} // namespace

extern "C" {

uint32_t lmh_abi_version(void) { return LMH_ABI_VERSION; }

lmh_usb_t *lmh_usb_create(const uint8_t *kit, size_t kit_len, uint64_t boot_id, int32_t *status) {
    int32_t dummy = 0;
    int32_t &st = status != nullptr ? *status : dummy;
    if (kit == nullptr) {
        st = s(lm::Status::InvalidArgument);
        return nullptr;
    }
    auto *h = new (std::nothrow) lmh_usb(boot_id);
    if (h == nullptr) {
        st = s(lm::Status::NoCapacity);
        return nullptr;
    }
    const lm::Status ls = h->usb.load_kit(lm::ByteView{kit, kit_len});
    st = s(ls);
    if (ls != lm::Status::Ok) {
        delete h;
        return nullptr;
    }
    return h;
}

void lmh_usb_destroy(lmh_usb_t *h) { delete h; }

int32_t lmh_usb_self(lmh_usb_t *h, uint8_t out[32]) {
    if (h == nullptr || out == nullptr) {
        return s(lm::Status::InvalidArgument);
    }
    const lm::DeviceId &id = h->usb.self();
    for (size_t i = 0; i < 32; ++i) {
        out[i] = id.bytes[i];
    }
    return s(lm::Status::Ok);
}

int32_t lmh_usb_open(lmh_usb_t *h, uint64_t now_us) {
    if (h == nullptr) {
        return s(lm::Status::InvalidArgument);
    }
    h->usb.open(t(now_us));
    return s(lm::Status::Ok);
}

void lmh_usb_close(lmh_usb_t *h) {
    if (h != nullptr) {
        h->usb.close();
    }
}

int32_t lmh_usb_feed(lmh_usb_t *h, const uint8_t *data, size_t len, uint64_t now_us) {
    if (h == nullptr || (data == nullptr && len != 0)) {
        return s(lm::Status::InvalidArgument);
    }
    h->usb.feed(lm::ByteView{data, len}, t(now_us));
    return s(lm::Status::Ok);
}

size_t lmh_usb_peek_tx(lmh_usb_t *h, uint8_t *out, size_t cap) {
    return h == nullptr || out == nullptr ? 0 : h->usb.peek_tx(lm::MutByteView{out, cap});
}

int32_t lmh_usb_consume_tx(lmh_usb_t *h, size_t n) {
    if (h == nullptr) {
        return s(lm::Status::InvalidArgument);
    }
    h->usb.consume_tx(n);
    return s(lm::Status::Ok);
}

int32_t lmh_usb_tick(lmh_usb_t *h, uint64_t now_us) {
    if (h == nullptr) {
        return s(lm::Status::InvalidArgument);
    }
    h->usb.tick(t(now_us));
    return s(lm::Status::Ok);
}

uint64_t lmh_usb_deadline_us(lmh_usb_t *h) { return h == nullptr ? UINT64_MAX : h->usb.deadline().us; }

int32_t lmh_usb_poll_event(lmh_usb_t *h, lmh_event_t *ev, uint8_t *buf, size_t cap, uint64_t now_us) {
    if (h == nullptr || ev == nullptr) {
        return s(lm::Status::InvalidArgument);
    }
    HostEvent e;
    if (!h->usb.peek_event(e)) {
        return 0;
    }
    if (e.payload.size() > cap || (buf == nullptr && !e.payload.empty())) {
        ev->payload_len = static_cast<uint32_t>(e.payload.size());
        return s(lm::Status::BufferTooSmall); // stays queued
    }
    (void)h->usb.next_event(e, t(now_us));
    ev->kind = static_cast<uint32_t>(e.kind);
    ev->gen = e.gen;
    ev->aux = e.aux;
    ev->lane = e.lane;
    ev->frame_bytes = e.frame_bytes;
    ev->payload_len = static_cast<uint32_t>(e.payload.size());
    for (size_t i = 0; i < e.payload.size(); ++i) {
        buf[i] = e.payload[i];
    }
    return 1;
}

int32_t lmh_usb_send(lmh_usb_t *h, uint32_t kind, uint32_t gen, const uint8_t *payload, size_t len,
                     uint64_t now_us) {
    if (h == nullptr || (payload == nullptr && len != 0) || kind < 3 || kind > 5) {
        return s(lm::Status::InvalidArgument);
    }
    return s(h->usb.send(static_cast<lm::gen::SerialKind>(kind), gen, lm::ByteView{payload, len}, t(now_us)));
}

int32_t lmh_usb_active(lmh_usb_t *h, uint32_t *gen, uint32_t *session_id) {
    if (h == nullptr) {
        return s(lm::Status::InvalidArgument);
    }
    if (gen != nullptr) {
        *gen = h->usb.link().session_gen();
    }
    if (session_id != nullptr) {
        *session_id = h->usb.link().session_id();
    }
    return h->usb.link().active() ? 1 : 0;
}

size_t lmh_usb_stats_count(void) { return 24; }

int32_t lmh_usb_stats(lmh_usb_t *h, lmh_stats_t *out) {
    if (h == nullptr || out == nullptr) {
        return s(lm::Status::InvalidArgument);
    }
    const lm::serial::UsbStats &st = h->usb.link().stats();
    const uint64_t v[24] = {st.rx_bytes,          st.rx_frames,         st.rx_cobs_bad,    st.rx_overflow,
                            st.rx_bad_frame,      st.rx_unsupported,    st.rx_unknown_session, st.rx_auth_fail,
                            st.rx_replay,         st.rx_malformed,      st.rx_credit_violation, st.rx_hello,
                            st.rx_edhoc_dropped,  st.tx_frames,         st.tx_partial,     st.tx_credit_blocked,
                            st.hs_started,        st.hs_failed,         st.hs_rejected,    st.sessions,
                            st.pings_rx,          h->usb.events_dropped(),
                            static_cast<uint64_t>(h->usb.link().last_failure()), 0};
    for (size_t i = 0; i < 24; ++i) {
        out->v[i] = v[i];
    }
    return s(lm::Status::Ok);
}

} // extern "C"
