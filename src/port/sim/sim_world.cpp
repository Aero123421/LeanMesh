#include "port/sim/sim_world.hpp"

#include "core/assert.hpp"
#include "port/sim/sim_node.hpp"

namespace lm::sim {

namespace {
constexpr uint32_t k_mac_ack_us = 100; // ACK turnaround after the frame (model constant)
}

World::World(const WorldOptions &opts) : opts_(opts), rng_(opts.seed) {}

World::~World() = default;

uint16_t World::add_node(const NodeOptions &opts) {
    const auto index = static_cast<uint16_t>(nodes_.size());
    // Locally administered unicast MAC: 02:4C:4D:00:<index>.
    MacAddr mac{{0x02, 0x4C, 0x4D, 0x00, static_cast<uint8_t>(index >> 8U),
                 static_cast<uint8_t>(index & 0xFFU)}};
    nodes_.push_back(std::make_unique<SimNode>(*this, index, mac, opts));
    const std::size_t n = nodes_.size();
    std::vector<LinkParams> grown(n * n);
    for (std::size_t a = 0; a + 1 < n; ++a) {
        for (std::size_t b = 0; b + 1 < n; ++b) {
            grown[a * n + b] = links_[a * (n - 1) + b];
        }
    }
    links_ = std::move(grown);
    return index;
}

SimNode &World::node(uint16_t index) {
    LM_ASSERT(index < nodes_.size());
    return *nodes_[index];
}

void World::set_link(uint16_t a, uint16_t b, const LinkParams &p) {
    const std::size_t n = nodes_.size();
    LM_ASSERT(a < n && b < n && a != b); // simulator API misuse
    links_[a * n + b] = p;
    links_[b * n + a] = p;
}

const LinkParams &World::link(uint16_t a, uint16_t b) const {
    LM_ASSERT(a < nodes_.size() && b < nodes_.size());
    return links_[static_cast<std::size_t>(a) * nodes_.size() + b];
}

void World::make_chain() {
    LinkParams up;
    up.up = true;
    for (std::size_t i = 0; i + 1 < nodes_.size(); ++i) {
        set_link(static_cast<uint16_t>(i), static_cast<uint16_t>(i + 1), up);
    }
}

void World::make_full() {
    LinkParams up;
    up.up = true;
    for (std::size_t a = 0; a < nodes_.size(); ++a) {
        for (std::size_t b = a + 1; b < nodes_.size(); ++b) {
            set_link(static_cast<uint16_t>(a), static_cast<uint16_t>(b), up);
        }
    }
}

int World::find_node_by_mac(const MacAddr &mac) const {
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i]->radio.mac() == mac) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

uint64_t World::airtime_us(std::size_t bytes) {
    // LR 250 kbit/s = 4 us/bit plus a fixed preamble/header allowance. A scheduling model only.
    return 1000 + static_cast<uint64_t>(bytes) * 8U * 4U;
}

bool World::lost(uint16_t permille) { return permille > 0 && (rng_() % 1000U) < permille; }

void World::push(Event ev) {
    ev.seq = seq_++;
    events_.push(ev);
}

void World::medium_transmit(uint16_t from, const MacAddr &dst, ByteView frame,
                            port::TxToken token) {
    LM_ASSERT(from < nodes_.size());
    SimNode &sender = *nodes_[from];
    const uint64_t air = airtime_us(frame.size());
    Event rx;
    rx.kind = EventKind::Rx;
    rx.radio.kind = port::RadioEvent::Kind::Rx;
    rx.radio.rx.src = sender.radio.mac();
    rx.radio.rx.broadcast = dst.is_broadcast();
    rx.radio.rx.rssi_valid = false; // the medium has no RF model; RSSI stays unknown
    rx.radio.rx.len = static_cast<uint8_t>(frame.size());
    for (std::size_t i = 0; i < frame.size(); ++i) {
        rx.radio.rx.bytes[i] = frame[i];
    }

    bool acked = dst.is_broadcast(); // ESP-NOW broadcast completes without a MAC ACK
    for (uint16_t j = 0; j < nodes_.size(); ++j) {
        if (j == from) {
            continue;
        }
        SimNode &r = *nodes_[j];
        const bool addressed = dst.is_broadcast() || r.radio.mac() == dst;
        if (!addressed) {
            continue;
        }
        const LinkParams &lp = link(from, j);
        if (!lp.up || !r.powered() || !r.radio.receiving() ||
            r.radio.channel() != sender.radio.channel() || lost(lp.loss_permille)) {
            continue;
        }
        rx.node = j;
        rx.at_us = now_us_ + air + lp.delay_us;
        rx.radio.rx.at = MonoTime{}; // stamped with the receiver clock on delivery
        push(rx);
        if (!dst.is_broadcast()) {
            acked = !lost(lp.ack_loss_permille);
        }
    }

    Event done;
    done.kind = EventKind::TxDone;
    done.node = from;
    done.node_epoch = sender.epoch();
    done.at_us =
        now_us_ + air + (dst.is_broadcast() ? 0 : k_mac_ack_us) + opts_.tx_callback_delay_us;
    done.radio.kind = port::RadioEvent::Kind::TxDone;
    done.radio.done.token = token;
    done.radio.done.result = acked ? port::TxResult::MacAcked : port::TxResult::MacFailed;
    push(done);
}

void World::inject(const MacAddr &from_mac, uint16_t via, const MacAddr &dst, ByteView frame) {
    Event rx;
    rx.kind = EventKind::Rx;
    rx.radio.kind = port::RadioEvent::Kind::Rx;
    rx.radio.rx.src = from_mac;
    rx.radio.rx.broadcast = dst.is_broadcast();
    rx.radio.rx.len = static_cast<uint8_t>(
        frame.size() > port::k_max_frame_bytes ? port::k_max_frame_bytes : frame.size());
    for (std::size_t i = 0; i < rx.radio.rx.len; ++i) {
        rx.radio.rx.bytes[i] = frame[i];
    }
    for (uint16_t j = 0; j < nodes_.size(); ++j) {
        if (j != via && (dst.is_broadcast() || nodes_[j]->radio.mac() == dst) && link(via, j).up) {
            rx.node = j;
            rx.at_us = now_us_ + airtime_us(frame.size()) + link(via, j).delay_us;
            push(rx);
        }
    }
}

void World::schedule_wake(uint16_t node, uint64_t at_us) {
    Event ev;
    ev.kind = EventKind::Wake;
    ev.node = node;
    ev.at_us = at_us < now_us_ ? now_us_ : at_us;
    push(ev);
}

void World::schedule_job_completion(uint16_t node, uint64_t at_us, uint32_t node_epoch,
                                    uint16_t table_index, uint32_t job_id, port::JobFn fn,
                                    void *arg) {
    Event ev;
    ev.kind = EventKind::JobDone;
    ev.node = node;
    ev.node_epoch = node_epoch;
    ev.at_us = at_us;
    ev.table_index = table_index;
    ev.job_id = job_id;
    ev.fn = fn;
    ev.arg = arg;
    push(ev);
}

bool World::next_event_time(uint64_t &t_us) const {
    if (events_.empty()) {
        return false;
    }
    t_us = events_.top().at_us;
    return true;
}

void World::run_until(uint64_t t_us) {
    while (!events_.empty() && events_.top().at_us <= t_us) {
        const Event ev = events_.top();
        events_.pop();
        if (ev.at_us > now_us_) {
            now_us_ = ev.at_us;
        }
        dispatch(ev);
    }
    if (t_us > now_us_) {
        now_us_ = t_us;
    }
}

void World::dispatch(const Event &ev) {
    SimNode &n = *nodes_[ev.node];
    switch (ev.kind) {
    case EventKind::Wake:
        n.on_wake_event(ev.at_us);
        return;
    case EventKind::Rx: {
        if (!n.powered()) {
            return;
        }
        port::RadioEvent re = ev.radio;
        re.rx.at = n.clock.now();
        n.radio.deliver(re);
        n.notify();
        return;
    }
    case EventKind::TxDone: {
        if (!n.powered() || n.epoch() != ev.node_epoch) {
            return;
        }
        port::RadioEvent re = ev.radio;
        re.done.at = n.clock.now();
        n.radio.deliver(re);
        n.notify();
        return;
    }
    case EventKind::JobDone: {
        if (!n.powered() || n.epoch() != ev.node_epoch) {
            return; // the worker died with the node: the job never completed
        }
        port::JobEnv env{n.store};
        const Status st = ev.fn(env, ev.arg);
        n.jobs.complete(port::JobCompletion{ev.table_index, ev.job_id, st});
        n.notify();
        return;
    }
    }
}

} // namespace lm::sim
