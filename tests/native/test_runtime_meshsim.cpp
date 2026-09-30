// The meshsim process itself: topology file, control protocol, raw TX, inject, callback delay and
// trace, through stdin/stdout exactly as the Python harness uses it.
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "lmtest.hpp"

namespace {

std::string write_file(const std::string &text) {
    char path[] = "/tmp/lm_topo_XXXXXX";
    const int fd = mkstemp(path);
    LM_CHECK(fd >= 0);
    const ssize_t n = write(fd, text.data(), text.size());
    LM_CHECK(n == static_cast<ssize_t>(text.size()));
    close(fd);
    return path;
}

// Runs meshsim with `args`, feeds `script` (one command per line) and returns all stdout.
std::string run_meshsim(const std::string &args, const std::string &script, int *exit_code) {
    const std::string sp = write_file(script);
    const std::string cmd = std::string(MESHSIM_EXE) + " " + args + " < " + sp + " 2>/dev/null";
    std::string out;
    FILE *p = popen(cmd.c_str(), "r");
    LM_CHECK(p != nullptr);
    char buf[4096];
    for (std::size_t n; p != nullptr && (n = fread(buf, 1, sizeof buf, p)) > 0;) {
        out.append(buf, n);
    }
    const int rc = p != nullptr ? pclose(p) : -1;
    *exit_code = rc == -1 ? -1 : WEXITSTATUS(rc);
    unlink(sp.c_str());
    return out;
}

bool has(const std::string &s, const char *needle) { return s.find(needle) != std::string::npos; }

} // namespace

LM_TEST("meshsim: topology file, start, rawtx over an allowlist link, callback delay, trace") {
    const std::string topo = write_file("# 0-1 linked, 2 isolated\nlink 0 1 0 2\n");
    int rc = 0;
    const std::string out = run_meshsim(
        "--nodes 3 --topology none --topology-file " + topo + " --seed 3",
        "start 0\nstart 1\nstart 2\ntrace on 64\ncb-delay 100 0\n"
        "rawtx 0 1 4c4d0101\nrawtx 0 2 4c4d0101\nrun 150\nrawtx 0 2 4c4d0101\nrun 300\n"
        "inject 1 0 0 4c4d0202\nrun 50\nnode 0\nnode 1\nnode 2\ntrace dump\nquit\n",
        &rc);
    unlink(topo.c_str());
    LM_CHECK_EQ(rc, 0);
    LM_CHECK(has(out, "\"event\":\"ready\""));
    LM_CHECK(!has(out, "\"ok\":false\"error"));
    // Node 1 heard the frame over the link; node 2 (no link) heard nothing.
    LM_CHECK(has(out, "\"node\":1,") && has(out, "\"rx_frames\":1"));
    LM_CHECK(has(out, "\"tx_mac_acked\":1"));
    // The immediate second rawtx hit the busy physical TX (local); the later one to the unlinked
    // node completes as one RF failure sample (no receiver, no MAC ACK).
    LM_CHECK(has(out, "\"status\":\"BUSY\""));
    LM_CHECK(has(out, "\"tx_local_refused\":1") && has(out, "\"tx_rf_failed\":1"));
    LM_CHECK(has(out, "\"kind\":\"tx_done\""));
    LM_CHECK(has(out, "\"kind\":\"lost\""));  // node 2: no link
    LM_CHECK(has(out, "\"kind\":\"inject\""));
}

LM_TEST("meshsim: a malformed topology file is rejected before the world runs") {
    const std::string topo = write_file("link 0 1\nlink 0 9\n");
    int rc = 0;
    const std::string out =
        run_meshsim("--nodes 2 --topology none --topology-file " + topo, "quit\n", &rc);
    unlink(topo.c_str());
    LM_CHECK(rc != 0);
    LM_CHECK(!has(out, "ready"));
}

LM_TEST_MAIN()
