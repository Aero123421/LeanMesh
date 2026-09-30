// --topology-file parser for meshsim (allowlist links, docs/18 §3).
#include <fstream>
#include <sstream>

#include "control.hpp"

namespace meshsim {

namespace {

bool parse_field(const std::string &s, uint64_t max, uint64_t &out) {
    return parse_u64(s, out) && out <= max;
}

} // namespace

bool load_topology(lm::sim::World &world, const std::string &path, std::string &err) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open " + path;
        return false;
    }
    struct Link {
        uint16_t a = 0;
        uint16_t b = 0;
        lm::sim::LinkParams p;
    };
    std::vector<Link> links; // applied only when the whole file is valid
    std::string line;
    for (unsigned no = 1; std::getline(in, line); ++no) {
        line = line.substr(0, line.find('#'));
        std::istringstream ls(line);
        Args tok;
        for (std::string t; ls >> t;) {
            tok.push_back(t);
        }
        if (tok.empty()) {
            continue;
        }
        Link l;
        uint64_t a = 0;
        uint64_t b = 0;
        uint64_t v = 0;
        const std::size_t n = world.node_count();
        const bool ok = tok[0] == "link" && tok.size() >= 3 && tok.size() <= 6 &&
                        parse_field(tok[1], n - 1, a) && parse_field(tok[2], n - 1, b) && a != b;
        if (!ok) {
            err = path + ":" + std::to_string(no) + ": expected `link <a> <b> [loss_permille] "
                                                    "[delay_ms] [ack_loss_permille]` with nodes < " +
                  std::to_string(n);
            return false;
        }
        l.a = static_cast<uint16_t>(a);
        l.b = static_cast<uint16_t>(b);
        l.p.up = true;
        if (tok.size() > 3 && parse_field(tok[3], 1000, v)) {
            l.p.loss_permille = static_cast<uint16_t>(v);
        } else if (tok.size() > 3) {
            err = path + ":" + std::to_string(no) + ": loss_permille 0..1000";
            return false;
        }
        if (tok.size() > 4 && parse_field(tok[4], 10000, v)) {
            l.p.delay_us = static_cast<uint32_t>(v * 1000);
        } else if (tok.size() > 4) {
            err = path + ":" + std::to_string(no) + ": delay_ms 0..10000";
            return false;
        }
        if (tok.size() > 5 && parse_field(tok[5], 1000, v)) {
            l.p.ack_loss_permille = static_cast<uint16_t>(v);
        } else if (tok.size() > 5) {
            err = path + ":" + std::to_string(no) + ": ack_loss_permille 0..1000";
            return false;
        }
        links.push_back(l);
    }
    for (const Link &l : links) {
        world.set_link(l.a, l.b, l.p);
    }
    return true;
}

} // namespace meshsim
