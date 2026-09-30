#include "port/sim/sim_ports.hpp"

#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"

namespace lm::sim {

// ---- SimClock ----------------------------------------------------------------------------------
MonoTime SimClock::now() const {
    const uint64_t local = world_.now_us() - boot_world_us_;
    const auto skew = static_cast<int64_t>(local) / 1000000 * drift_ppm_ +
                      static_cast<int64_t>(local % 1000000) * drift_ppm_ / 1000000;
    return MonoTime{static_cast<uint64_t>(static_cast<int64_t>(local) + skew)};
}

// ---- SimRadio ----------------------------------------------------------------------------------
Status SimRadio::start(const port::RfProfile &profile) {
    if (start_fault_count > 0) {
        --start_fault_count;
        return Status::RecoveryRequired;
    }
    if (!profile.deployment_approved) {
        return Status::RfProfileUnapproved;
    }
    if (profile.channel < 1 || profile.channel > 13 ||
        (profile.allowed_channels_mask & (1U << profile.channel)) == 0) {
        return Status::InvalidArgument;
    }
    allowed_mask_ = profile.allowed_channels_mask;
    channel_ = profile.channel;
    ++driver_generation_; // a fresh driver instance: older callbacks never match
    tx_in_flight_ = false;
    peer_count_ = 0; // a driver (re)initialisation starts with an empty peer table
    on_ = true;
    held_ = false;
    return Status::Ok;
}

void SimRadio::hold_rx() {
    if (late_pending_ && on_) { // a callback that ran just before the flag
        (void)ring_.push(late_.rx);
    }
    late_pending_ = false;
    held_ = true;
}

Status SimRadio::stop() {
    if (stop_fault_count > 0) {
        --stop_fault_count;
        return Status::RecoveryRequired;
    }
    on_ = false;
    tx_in_flight_ = false;
    peer_count_ = 0;
    port::RadioRx rx; // like IdfRadio::stop(): what the stopped driver had queued is gone (FIX10-D8 hands it over first)
    while (ring_.pop(rx)) {
    }
    return Status::Ok;
}

Status SimRadio::set_channel(uint8_t channel) {
    if (set_channel_fault_count > 0) {
        --set_channel_fault_count;
        return Status::RecoveryRequired;
    }
    if (!on_ || channel < 1 || channel > 13 || (allowed_mask_ & (1U << channel)) == 0) {
        return Status::InvalidArgument;
    }
    channel_ = channel;
    return Status::Ok;
}

bool SimRadio::has_peer(const MacAddr &mac) const {
    for (std::size_t i = 0; i < peer_count_; ++i) {
        if (peers_[i] == mac) {
            return true;
        }
    }
    return false;
}

Status SimRadio::add_peer(const MacAddr &mac) {
    if (!on_) {
        return Status::Conflict; // ESP_ERR_ESPNOW_NOT_INIT
    }
    if (has_peer(mac)) {
        return Status::Ok;
    }
    if (peer_count_ == k_max_peers) {
        return Status::NoCapacity;
    }
    peers_[peer_count_++] = mac;
    peak_peers_ = peak_peers_ > peer_count_ ? peak_peers_ : peer_count_;
    return Status::Ok;
}

Status SimRadio::remove_peer(const MacAddr &mac) {
    for (std::size_t i = 0; i < peer_count_; ++i) {
        if (peers_[i] == mac) {
            peers_[i] = peers_[peer_count_ - 1];
            --peer_count_;
            return Status::Ok;
        }
    }
    return Status::NotFound;
}

Status SimRadio::transmit(const MacAddr &dst, ByteView frame, port::TxToken token) {
    if (!on_ || frame.empty() || frame.size() > port::k_max_frame_bytes) {
        return Status::InvalidArgument;
    }
    if (tx_fault_count > 0) {
        --tx_fault_count;
        return tx_fault;
    }
    if (tx_in_flight_) {
        return Status::Busy;
    }
    if (!has_peer(dst)) {
        return Status::InvalidArgument; // like ESP_ERR_ESPNOW_NOT_FOUND: register peers first
    }
    tx_in_flight_ = true;
    world_.medium_transmit(node_, dst, frame, token);
    return Status::Ok;
}

bool SimRadio::poll(port::RadioEvent &out) {
    if (done_ring_.pop(out.done)) {
        out.kind = port::RadioEvent::Kind::TxDone;
        return true;
    }
    if (ring_.pop(out.rx)) {
        out.kind = port::RadioEvent::Kind::Rx;
        return true;
    }
    return false;
}

void SimRadio::deliver(const port::RadioEvent &ev) {
    if (ev.kind == port::RadioEvent::Kind::TxDone) {
        // A callback of an older driver instance still reaches the owner (worst case) but must not
        // clear the in-flight state of the current one.
        if (ev.done.token.driver_generation == driver_generation_) {
            tx_in_flight_ = false;
        }
        (void)done_ring_.push(ev.done);
    } else if (on_ && !held_) {
        (void)ring_.push(ev.rx); // overflow is counted by the ring (rx_dropped)
    }
}

void SimRadio::power_cut() {
    on_ = false;
    tx_in_flight_ = false;
    peer_count_ = 0;
    ++driver_generation_;
    port::RadioRx rx;
    while (ring_.pop(rx)) {
    }
    port::RadioTxDone done;
    while (done_ring_.pop(done)) {
    }
}

// ---- SimJobs -----------------------------------------------------------------------------------
Status SimJobs::submit(uint16_t table_index, uint32_t job_id, port::JobFn fn, void *arg) {
    if (fn == nullptr) {
        return Status::InvalidArgument;
    }
    if (queued_ + done_.size() >= k_queue) {
        return Status::Busy;
    }
    ++queued_;
    world_.schedule_job_completion(node_, world_.now_us() + latency_us, epoch_, table_index, job_id,
                                   fn, arg);
    return Status::Ok;
}

bool SimJobs::poll(port::JobCompletion &out) { return done_.pop(out); }

void SimJobs::complete(const port::JobCompletion &c) {
    if (queued_ > 0) {
        --queued_;
    }
    (void)done_.push(c); // capacity is reserved at submit
}

void SimJobs::power_cut() {
    queued_ = 0;
    done_.clear();
}

void SimJobs::random(MutByteView out) {
    // xorshift64*: deterministic per node and seed. SIMULATION ONLY; the IDF port uses the
    // hardware RNG and never accepts a seed (docs/06 §8).
    for (std::size_t i = 0; i < out.size(); ++i) {
        rng_state_ ^= rng_state_ >> 12U;
        rng_state_ ^= rng_state_ << 25U;
        rng_state_ ^= rng_state_ >> 27U;
        out[i] = static_cast<uint8_t>((rng_state_ * 0x2545F4914F6CDD1DULL) >> 56U);
    }
}

// ---- DirectOwnerCall ---------------------------------------------------------------------------
Reply DirectOwnerCall::call(const Command &cmd) {
    lm_context_t *ctx = node_.ctx();
    if (ctx == nullptr) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    const Reply r = ctx->engine.execute(cmd, node_.clock.now());
    node_.notify();
    return r;
}

} // namespace lm::sim
