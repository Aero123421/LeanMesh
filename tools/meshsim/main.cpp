// meshsim: N real LeanMesh cores (lm_context + Engine) on simulated ports and a simulated medium.
// The root (node 0) serial port is a pty so the real FastAPI host can drive it end to end.
// SIMULATION ONLY: results are protocol evidence, never RF/range/power/hardware evidence.
//
//   meshsim [--nodes N] [--topology chain|full|none] [--topology-file F] [--clock virtual|realtime] [--seed S]
//           [--serial-pty] [--serial-bridge] [--no-boot]
#include <poll.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "control.hpp"
#include "port/sim/sim_node.hpp"
#include "pty.hpp"

namespace {

struct Options {
    unsigned nodes = 2;
    std::string topology = "chain";
    meshsim::ClockMode clock = meshsim::ClockMode::Virtual;
    uint64_t seed = 1;
    bool serial_pty = false;
    bool serial_bridge = false;
    bool boot = true;
    std::string topology_file; // links on top of --topology (usually with `none`)
};

int usage() {
    std::fprintf(
        stderr,
        "usage: meshsim [--nodes N] [--topology chain|full|none] [--topology-file F]\n"
        "               [--clock virtual|realtime] [--seed S] [--serial-pty] [--serial-bridge] [--no-boot]\n");
    return 2;
}

bool parse(int argc, char **argv, Options &o) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        const bool has_value = i + 1 < argc;
        if (a == "--nodes" && has_value) {
            o.nodes = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 10));
        } else if (a == "--topology" && has_value) {
            o.topology = argv[++i];
        } else if (a == "--topology-file" && has_value) {
            o.topology_file = argv[++i];
        } else if (a == "--clock" && has_value) {
            const std::string v = argv[++i];
            if (v != "virtual" && v != "realtime") {
                return false;
            }
            o.clock = v == "virtual" ? meshsim::ClockMode::Virtual : meshsim::ClockMode::Realtime;
        } else if (a == "--seed" && has_value) {
            o.seed = std::strtoull(argv[++i], nullptr, 10);
        } else if (a == "--serial-pty") {
            o.serial_pty = true;
        } else if (a == "--serial-bridge") {
            o.serial_bridge = true;
        } else if (a == "--no-boot") {
            o.boot = false;
        } else {
            return false;
        }
    }
    return o.nodes >= 1 && o.nodes <= 256 &&
           (o.topology == "chain" || o.topology == "full" || o.topology == "none");
}

uint64_t wall_us() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count());
}

void reply(const std::string &line) {
    std::fputs(line.c_str(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

} // namespace

int main(int argc, char **argv) {
    Options opt;
    if (!parse(argc, argv, opt)) {
        return usage();
    }
    lm::sim::WorldOptions wo;
    wo.seed = opt.seed;
    lm::sim::World world(wo);
    for (unsigned i = 0; i < opt.nodes; ++i) {
        lm::sim::NodeOptions no;
        no.role = i == 0 ? lm::Role::Root : lm::Role::Relay;
        (void)world.add_node(no);
    }
    if (opt.topology == "chain") {
        world.make_chain();
    } else if (opt.topology == "full") {
        world.make_full();
    }
    if (!opt.topology_file.empty()) {
        std::string err;
        if (!meshsim::load_topology(world, opt.topology_file, err)) {
            std::fprintf(stderr, "meshsim: %s\n", err.c_str());
            return 1;
        }
    }
    meshsim::Pty pty;
    if (opt.serial_pty && !pty.open()) {
        std::perror("meshsim: pty");
        return 1;
    }
    if (opt.boot) {
        for (unsigned i = 0; i < opt.nodes; ++i) {
            const lm::Status st = world.node(static_cast<uint16_t>(i)).boot();
            if (st != lm::Status::Ok) {
                std::fprintf(stderr, "meshsim: node %u boot failed: %s\n", i, lm::status_name(st));
                return 1;
            }
        }
    }
    meshsim::Sim sim{world, opt.clock, opt.serial_pty ? &pty : nullptr};
    sim.bridge = opt.serial_bridge && opt.serial_pty;
    reply(std::string("{\"event\":\"ready\",\"nodes\":") + std::to_string(opt.nodes) +
          ",\"clock\":\"" + (opt.clock == meshsim::ClockMode::Virtual ? "virtual" : "realtime") +
          "\",\"serial_pty\":\"" + (opt.serial_pty ? pty.slave_path() : "") + "\"}");

    const uint64_t start = wall_us();
    std::string pending;
    while (!sim.quit) {
        if (opt.clock == meshsim::ClockMode::Realtime) {
            world.run_until(wall_us() - start);
        }
        int timeout_ms = -1;
        uint64_t next = 0;
        if (opt.clock == meshsim::ClockMode::Realtime && world.next_event_time(next)) {
            const uint64_t now = wall_us() - start;
            timeout_ms = next <= now ? 0 : static_cast<int>((next - now + 999) / 1000);
        }
        pollfd fds[2] = {{STDIN_FILENO, POLLIN, 0}, {pty.master_fd(), POLLIN, 0}};
        const nfds_t nfds = opt.serial_pty ? 2 : 1;
        if (::poll(fds, nfds, timeout_ms) < 0) {
            std::perror("meshsim: poll");
            return 1;
        }
        if (opt.serial_pty && (fds[1].revents & POLLIN) != 0) {
            uint8_t buf[512];
            for (std::size_t n; (n = pty.read(buf, sizeof buf)) > 0;) {
                meshsim::on_serial_rx(sim, buf, n);
            }
        }
        if ((fds[0].revents & (POLLIN | POLLHUP)) != 0) {
            char buf[1024];
            const ssize_t n = ::read(STDIN_FILENO, buf, sizeof buf);
            if (n <= 0) {
                break; // controller closed stdin: exit
            }
            pending.append(buf, static_cast<std::size_t>(n));
            for (std::size_t pos; (pos = pending.find('\n')) != std::string::npos;) {
                const std::string line = pending.substr(0, pos);
                pending.erase(0, pos + 1);
                if (opt.clock == meshsim::ClockMode::Realtime) {
                    world.run_until(wall_us() - start);
                }
                reply(meshsim::execute(sim, line));
                if (sim.quit) {
                    break;
                }
            }
        }
    }
    return 0;
}
