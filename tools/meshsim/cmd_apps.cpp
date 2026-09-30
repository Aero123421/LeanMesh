// meshsim commands that run the example applications of examples/apps (G6, LC12) on a simulated node. The applications
// use only the public C API; this file only supplies their platform (an output driver, the clock). Bench only.
//   app-equipment <node> [fail]         poll + answer the node's commands; `fail` makes the driver refuse from now on
//   app-battery <node> <mv> <percent>   one periodic battery report to the root application (term 1, ttl 60 s)
#include <cinttypes>
#include <cstdio>
#include <map>
#include <string>

#include "battery_measurement.h"
#include "control.hpp"
#include "equipment_control.h"
#include "port/sim/sim_node.hpp"

namespace meshsim {

namespace {

struct EquipmentBench {
    equipment_t eq{};
    bool fail = false;
    unsigned drive_calls = 0;
};

int drive(void *user, uint8_t) {
    auto *b = static_cast<EquipmentBench *>(user);
    ++b->drive_calls;
    return b->fail ? 1 : 0;
}

} // namespace

std::string cmd_app_equipment(Sim &sim, const Args &a) {
    static std::map<uint16_t, EquipmentBench> benches;
    uint16_t i = 0;
    if ((a.size() != 2 && !(a.size() == 3 && a[2] == "fail")) || !parse_node(sim, a[1], i) ||
        sim.world.node(i).ctx() == nullptr) {
        return error("usage: app-equipment <node> [fail] (node must be started)");
    }
    auto it = benches.find(i);
    if (it == benches.end()) {
        it = benches.emplace(i, EquipmentBench{}).first;
        equipment_init(&it->second.eq, drive, &it->second);
    }
    it->second.fail = it->second.fail || a.size() == 3;
    const unsigned answered = equipment_poll(sim.world.node(i).ctx(), &it->second.eq);
    sim.world.node(i).notify();
    char buf[200];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"answered\":%u,\"on\":%u,\"revision\":%u,\"applied\":%u,\"rejected\":%u,\"drive_calls\":%u}",
                  answered, it->second.eq.on, it->second.eq.revision, it->second.eq.applied, it->second.eq.rejected,
                  it->second.drive_calls);
    return buf;
}

std::string cmd_app_battery(Sim &sim, const Args &a) {
    static std::map<uint16_t, battery_t> batteries;
    uint16_t i = 0;
    uint64_t mv = 0;
    uint64_t pct = 0;
    if (a.size() != 4 || !parse_node(sim, a[1], i) || !parse_u64(a[2], mv) || !parse_u64(a[3], pct) || mv > 65535 ||
        pct > 100 || sim.world.node(i).ctx() == nullptr) {
        return error("usage: app-battery <node> <millivolts> <percent> (node must be started)");
    }
    auto it = batteries.find(i);
    if (it == batteries.end()) {
        it = batteries.emplace(i, battery_t{}).first;
        battery_init(&it->second, 60'000);
    }
    const uint64_t now_ms = sim.world.node(i).clock.now().to_ms();
    lm_operation_id_t op = 0;
    const lm_status_t st = battery_report(sim.world.node(i).ctx(), &it->second, now_ms, 60'000,
                                          static_cast<uint16_t>(mv), static_cast<uint8_t>(pct), &op);
    sim.world.node(i).notify();
    char buf[160];
    std::snprintf(buf, sizeof buf, "{\"ok\":%s,\"status\":\"%s\",\"operation\":%" PRIu64 ",\"sequence\":%u,\"due\":%s}",
                  st == LM_STATUS_OK ? "true" : "false", st == LM_STATUS_OK ? "OK" : "REFUSED", op, it->second.sequence,
                  battery_due(&it->second, now_ms) ? "true" : "false");
    return buf;
}

} // namespace meshsim
