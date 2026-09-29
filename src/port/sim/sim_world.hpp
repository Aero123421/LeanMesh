// Discrete-event simulation world for meshsim and native integration tests.
// Single thread, virtual time in microseconds, deterministic for a given seed: events are ordered
// by (time, insertion sequence) and all randomness comes from the seeded generator.
// The medium models an allowlist topology (HIL-style neighbour allowlist, docs/18 §3), per-link
// loss and delay, MAC-ACK loss, TX-callback delay and one channel per node. It is a protocol test
// bench, NOT an RF model: simulated success is never RF, range or power evidence (AGENTS.md).
#pragma once

#include <cstdint>
#include <memory>
#include <queue>
#include <random>
#include <vector>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/ports.hpp"
#include "core/time.hpp"

namespace lm::sim {

class SimNode;
struct NodeOptions;

struct LinkParams {
    bool up = false;
    uint16_t loss_permille = 0;     // frame not received
    uint16_t ack_loss_permille = 0; // received, but the sender sees MacFailed
    uint32_t delay_us = 1000;       // propagation + receiver driver latency
};

struct WorldOptions {
    uint64_t seed = 1;
    uint32_t tx_callback_delay_us = 0; // extra delay before the TX-done callback
};

class World {
  public:
    explicit World(const WorldOptions &opts);
    ~World();
    World(const World &) = delete;
    World &operator=(const World &) = delete;

    [[nodiscard]] uint64_t now_us() const { return now_us_; }
    [[nodiscard]] const WorldOptions &options() const { return opts_; }
    WorldOptions &options() { return opts_; }

    // Creates a node (unpowered). Returns its index.
    uint16_t add_node(const NodeOptions &opts);
    [[nodiscard]] std::size_t node_count() const { return nodes_.size(); }
    SimNode &node(uint16_t index);

    // Symmetric allowlist link.
    void set_link(uint16_t a, uint16_t b, const LinkParams &p);
    [[nodiscard]] const LinkParams &link(uint16_t a, uint16_t b) const;
    void make_chain(); // 0-1-2-...-(n-1)
    void make_full();  // every pair

    // Advances virtual time, processing every event with time <= t_us in order.
    void run_until(uint64_t t_us);
    // Time of the next pending event (false when none).
    [[nodiscard]] bool next_event_time(uint64_t &t_us) const;

    // --- used by the sim ports -------------------------------------------------------------------
    // Transmission from node `from` (radio already accepted it). Schedules RX at receivers and the
    // TX-done callback at the sender.
    void medium_transmit(uint16_t from, const MacAddr &dst, ByteView frame, port::TxToken token);
    // Raw injection as if sent with `from_mac` (attacker/replay tests); no TX-done callback.
    void inject(const MacAddr &from_mac, uint16_t via, const MacAddr &dst, ByteView frame);
    void schedule_wake(uint16_t node, uint64_t at_us);
    void schedule_job_completion(uint16_t node, uint64_t at_us, uint32_t node_epoch,
                                 uint16_t table_index, uint32_t job_id, port::JobFn fn, void *arg);
    uint64_t random_u64() { return rng_(); }
    [[nodiscard]] int find_node_by_mac(const MacAddr &mac) const;

  private:
    enum class EventKind : uint8_t { Wake, Rx, TxDone, JobDone };
    struct Event {
        uint64_t at_us = 0;
        uint64_t seq = 0;
        EventKind kind = EventKind::Wake;
        uint16_t node = 0;
        uint32_t node_epoch = 0; // power cycles invalidate pending radio/job events
        port::RadioEvent radio;
        uint16_t table_index = 0;
        uint32_t job_id = 0;
        port::JobFn fn = nullptr;
        void *arg = nullptr;
    };
    struct Later {
        bool operator()(const Event &a, const Event &b) const {
            return a.at_us != b.at_us ? a.at_us > b.at_us : a.seq > b.seq;
        }
    };

    void push(Event ev);
    void dispatch(const Event &ev);
    [[nodiscard]] static uint64_t airtime_us(std::size_t bytes);
    [[nodiscard]] bool lost(uint16_t permille);

    WorldOptions opts_;
    uint64_t now_us_ = 0;
    uint64_t seq_ = 0;
    std::mt19937_64 rng_;
    std::vector<std::unique_ptr<SimNode>> nodes_;
    std::vector<LinkParams> links_; // n*n, symmetric
    std::priority_queue<Event, std::vector<Event>, Later> events_;
};

} // namespace lm::sim
