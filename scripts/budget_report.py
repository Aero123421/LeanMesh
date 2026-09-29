#!/usr/bin/env python3
"""Budget report (docs/16): sizeof per profile, fixed RAM against the profile targets and
first-party SLOC per module. A report, not a gate: it exits non-zero only when it cannot measure.

  scripts/budget_report.py [--native-build DIR] [--idf-build DIR]... [--json FILE]

--native-build  native CMake build containing tools/budget_probe (default $LEANMESH_NATIVE_BUILD or
                ~/.cache/leanmesh/native); sizes are `nm -S` of the lm_budget_probe_* libraries.
                Skipped when it has no probe libraries and an --idf-build is given (IDF-only jobs).
--idf-build     an ESP-IDF build of firmware/example_node (repeatable: the LEAF and the ROOT build
                of scripts/build_targets.sh --profile). The first one compiles the probe once per
                profile with its compile command of src/core/engine.cpp (the SoC compiler's sizes).
                Each build's link map gives libleanmesh.a's static DRAM/flash (esp_idf_size); its
                image is compared with build-records/T01-baseline-size.json (docs/16 flash diff).

"Fixed RAM" = the workspace (lm_context) + libleanmesh.a's static DRAM from the map of an IDF build
of that profile (task stacks, queues, radio rings; ROOT: the USB serial adapter). Without such a
build the static part is estimated from sizeof and the stack/ring constants in src/port/idf and
src/serial/idf_serial.cpp (task control blocks and queues are then missing: a few hundred bytes).
Vendor heap (PSA, Wi-Fi) and the crypto peak are NOT included (docs/16 lists them separately).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROFILES = ("leaf", "relay", "root")
PROBE = REPO / "tools" / "budget_probe" / "probe.cpp"
SYMBOL = re.compile(r"^[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+[BbDdCc]\s+lm_probe__(\w+)$")

# docs/16 budget sets. "sdk" = first-party C/C++ compiled into the firmware (core + security + store
# + capi + root/serial + port/idf): the 16,000 SLOC line.
SLOC_MODULES = (
    ("src/core", "sdk", False),  # top-level core files only; subdirectories are listed below
    *((f"src/core/{m}", "sdk", True) for m in (
        "wire", "radio", "link", "member", "route", "delivery", "sched", "group", "channel",
        "power", "diag")),
    *((f"src/{m}", "sdk", True)
      for m in ("security", "store", "capi", "root", "serial", "port/idf")),
    ("src/port/sim", "native-only", True), ("src/hostnative", "native-only", True),
    ("tools", "tools", True), ("tests/native", "tests", True),
)
C_SUFFIXES = {".c", ".h", ".cpp", ".hpp"}


def c_sloc(text: str) -> int:
    """Non-blank lines that are not only comment (// and /* */; string contents are not parsed)."""
    count = 0
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        code = ""
        i = 0
        while i < len(line):
            if in_block:
                end = line.find("*/", i)
                if end < 0:
                    i = len(line)
                else:
                    in_block = False
                    i = end + 2
            elif line.startswith("//", i):
                break
            elif line.startswith("/*", i):
                in_block = True
                i += 2
            else:
                code += line[i]
                i += 1
        if code.strip():
            count += 1
    return count


def py_sloc(text: str) -> int:
    return sum(1 for raw in text.splitlines() if raw.strip() and not raw.strip().startswith("#"))


def sloc_report() -> dict:
    modules = {}
    for rel, group, recursive in SLOC_MODULES:
        base = REPO / rel
        if not base.is_dir():
            continue
        files = base.rglob("*") if recursive else base.iterdir()
        n = sum(c_sloc(f.read_text(errors="replace")) for f in files
                if f.is_file() and f.suffix in C_SUFFIXES)
        modules[rel] = {"group": group, "sloc": n}
    host = REPO / "host"
    py = {"host (excl. tests)": 0, "host/tests": 0}
    for f in host.rglob("*.py"):
        key = "host/tests" if "tests" in f.relative_to(host).parts else "host (excl. tests)"
        py[key] += py_sloc(f.read_text(errors="replace"))
    groups: dict[str, int] = {}
    for m in modules.values():
        groups[m["group"]] = groups.get(m["group"], 0) + m["sloc"]
    return {"modules": modules, "groups": groups, "python": py,
            "budget": {"sdk_c_cpp": 16000, "python_host": 6000}}


def nm_sizes(nm: str, obj: Path) -> dict[str, int]:
    out = subprocess.run([nm, "-S", str(obj)], check=True, capture_output=True, text=True).stdout
    sizes = {}
    for line in out.splitlines():
        m = SYMBOL.match(line.strip())
        if m:
            sizes[m.group(2)] = int(m.group(1), 16) - 1  # the probe adds one byte (see probe.cpp)
    if not sizes:
        raise SystemExit(f"no lm_probe symbols in {obj}")
    return sizes


def native_sizes(build: Path) -> dict[str, dict[str, int]] | None:
    libs = {p: build / "tools" / "budget_probe" / f"liblm_budget_probe_{p}.a" for p in PROFILES}
    if not all(lib.is_file() for lib in libs.values()):
        return None
    nm = shutil.which("nm") or sys.exit("nm not found")
    return {p: nm_sizes(nm, lib) for p, lib in libs.items()}


def idf_sizes(build: Path) -> dict[str, dict[str, int]]:
    """Compiles the probe with the SoC compiler of an existing ESP-IDF build, once per profile."""
    cc = json.loads((build / "compile_commands.json").read_text())
    entry = next((e for e in cc if e["file"].endswith("src/core/engine.cpp")), None)
    if entry is None:
        sys.exit(f"{build}: no compile command for src/core/engine.cpp (not a LeanMesh build?)")
    args = shlex.split(entry["command"]) if "command" in entry else list(entry["arguments"])
    # The probe of the source tree the build compiled (its sizes are that tree's), else this one's.
    tree_probe = Path(entry["file"]).resolve().parents[2] / "tools" / "budget_probe" / "probe.cpp"
    probe = tree_probe if tree_probe.is_file() else PROBE
    compiler = args[0]
    nm = re.sub(r"(g\+\+|gcc|c\+\+)$", "nm", compiler)
    res = {}
    with tempfile.TemporaryDirectory() as tmp:
        obj = Path(tmp) / "probe.o"
        for p in PROFILES:
            cmd = []
            skip = False
            for a in args:
                if skip:
                    skip = False
                    continue
                if a in ("-o", "-c", "-MF", "-MT"):
                    skip = True
                    continue
                if a.startswith("-DLM_BUILD_PROFILE_") or a in ("-MD", "-MMD"):
                    continue
                cmd.append(a)
            cmd += [f"-DLM_BUILD_PROFILE_{p.upper()}", "-o", str(obj), "-c", str(probe)]
            subprocess.run(cmd, cwd=entry["directory"], check=True)
            res[p] = nm_sizes(nm, obj)
    return res


def idf_build_info(build: Path) -> dict:
    """Profile/target of an IDF build, libleanmesh.a static memory (map), image size vs baseline."""
    cfg = (build / "config" / "sdkconfig.h").read_text()
    prof = next((p for p in PROFILES if f"CONFIG_LEANMESH_PROFILE_{p.upper()} 1" in cfg), None)
    target = re.search(r'CONFIG_IDF_TARGET "(\w+)"', cfg)
    info: dict = {"build": str(build), "profile": prof,
                  "target": target.group(1) if target else None,
                  "static": None, "image_bytes": None, "baseline_image_bytes": None}
    maps = sorted(build.glob("*.map"))
    pythons = [sys.executable]
    if os.environ.get("IDF_PYTHON_ENV_PATH"):
        pythons.append(str(Path(os.environ["IDF_PYTHON_ENV_PATH"]) / "bin" / "python"))
    cache = build / "CMakeCache.txt"  # the Python the build used has esp_idf_size
    if cache.is_file():
        found = re.search(r"^PYTHON:\w+=(.+)$", cache.read_text(), re.MULTILINE)
        if found:
            pythons.append(found.group(1).strip())
    for py in pythons if maps else []:
        cmd = [py, "-m", "esp_idf_size", "--archives", "--format", "json2", str(maps[0])]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            continue
        archives = json.loads(r.stdout).items()
        lib = next((v for k, v in archives if k.endswith("libleanmesh.a")), None)
        if lib is not None:
            mem = lib["memory_types"]
            dram = mem.get("DRAM", {}).get("sections", {})
            info["static"] = {"dram_bss": dram.get(".dram0.bss", {}).get("size", 0),
                              "dram_data": dram.get(".dram0.data", {}).get("size", 0),
                              "flash_code": mem.get("Flash Code", {}).get("size", 0),
                              "flash_data": mem.get("Flash Data", {}).get("size", 0)}
        break
    size = build / "size.json"
    base = REPO / "build-records" / "T01-baseline-size.json"
    if size.is_file() and base.is_file() and info["target"]:
        raw = size.read_text()
        info["image_bytes"] = json.loads(raw[raw.index("{"):]).get("total_size")
        base_targets = json.loads(base.read_text())["targets"]
        info["baseline_image_bytes"] = base_targets.get(info["target"], {}).get("image_total_bytes")
    return info


def constant(path: str, name: str) -> int:
    m = re.search(rf"\b{name}\s*=\s*(\d+)", (REPO / path).read_text())
    if not m:
        sys.exit(f"{path}: constant {name} not found")
    return int(m.group(1))


def fixed_ram(sizes: dict[str, dict[str, int]], builds: list[dict]) -> dict[str, dict]:
    owner = constant("src/port/idf/idf_owner.hpp", "k_stack_bytes")
    worker = constant("src/port/idf/idf_jobs.hpp", "k_stack_bytes")
    usb_stack = constant("src/serial/idf_serial.cpp", "k_task_stack_bytes")
    usb_ring = constant("src/serial/idf_serial.cpp", "k_rx_ring_bytes")
    targets = json.loads((REPO / "config" / "profiles.json").read_text())["profiles"]
    res = {}
    for p in PROFILES:
        s = sizes[p]
        items = {"workspace (lm_context)": s["ctx"]}
        mapped = next((b for b in builds if b["profile"] == p and b["static"]), None)
        if mapped:
            st = mapped["static"]
            items["libleanmesh.a static DRAM (map)"] = st["dram_bss"] + st["dram_data"]
            basis = f"map of {mapped['build']}"
        else:
            items["owner task stack"] = owner
            items["worker task stack"] = worker
            items["radio (rx/done rings)"] = s["platform__radio"]
            if p == "root":
                items["USB serial adapter (RootUsb)"] = s["root__usb"]
                items["USB task stack + byte ring"] = usb_stack + usb_ring
            basis = "estimate (sizeof + stack/ring constants)"
        total = sum(items.values())
        res[p] = {"items": items, "total": total, "target": targets[p]["ram_target_bytes"],
                  "basis": basis}
    return res


def print_sizes(title: str, sizes: dict[str, dict[str, int]]) -> None:
    """One row per probe symbol, indented along its ownership path (`a__b__c`)."""
    print(f"\n## sizeof per profile ({title})\n")
    print(f"{'object':62} {'LEAF':>8} {'RELAY':>8} {'ROOT':>8}")
    group = None
    for name in sorted(sizes["leaf"], key=lambda n: (n.startswith("each__"), n)):
        parts = name.split("__")
        if parts[0] != group:
            group = parts[0]
            if group not in sizes["leaf"]:
                print(f"[{group}]")
        label = "  " * (len(parts) - 1) + parts[-1] if parts[0] != "each" else f"one {parts[-1]}"
        row = [sizes[p].get(name, 0) for p in PROFILES]
        print(f"{label:62} {row[0]:8} {row[1]:8} {row[2]:8}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_native = os.environ.get("LEANMESH_NATIVE_BUILD",
                                    str(Path.home() / ".cache/leanmesh/native"))
    ap.add_argument("--native-build", type=Path, default=Path(default_native))
    ap.add_argument("--idf-build", type=Path, action="append", default=[])
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()

    report: dict = {"native": native_sizes(a.native_build)}
    builds = [idf_build_info(b) for b in a.idf_build]
    if report["native"] is None and not builds:
        sys.exit(f"{a.native_build}: no lm_budget_probe_* libraries (build the native tree) "
                 "and no --idf-build given")
    if builds:
        report["idf"] = {"sizes": idf_sizes(a.idf_build[0]), "builds": builds}
    basis = report["idf"]["sizes"] if builds else report["native"]
    report["fixed_ram"] = fixed_ram(basis, builds)
    report["sloc"] = sloc_report()

    print("# LeanMesh budget report (docs/16; a report, not a gate)")
    if report["native"] is not None:
        print_sizes("native x86-64", report["native"])
    if builds:
        print_sizes(f"SoC compiler of {a.idf_build[0]}", report["idf"]["sizes"])
        print("\n## IDF builds\n")
        for b in builds:
            st = b["static"]
            line = f"{b['target']} {b['profile']}: "
            line += (f"libleanmesh.a DRAM .bss {st['dram_bss']} + .data {st['dram_data']} B, "
                     f"flash code {st['flash_code']} + data {st['flash_data']} B"
                     if st else "no map data")
            if b["image_bytes"] and b["baseline_image_bytes"]:
                d = b["image_bytes"] - b["baseline_image_bytes"]
                line += (f"; image {b['image_bytes']} B = baseline "
                         f"{b['baseline_image_bytes']} B {d:+d} B")
            print(line)
    print("\n## fixed RAM vs target (workspace + static; excludes vendor heap and crypto peak)\n")
    for p in PROFILES:
        f = report["fixed_ram"][p]
        print(f"{p.upper():5} total {f['total']:7} B  target {f['target']:6} B  "
              f"({f['total'] - f['target']:+d} B)  [{f['basis']}]")
        for k, v in f["items"].items():
            print(f"        {k:40} {v:7}")
    s = report["sloc"]
    print("\n## first-party SLOC (non-blank, non-comment)\n")
    for rel, m in s["modules"].items():
        print(f"{rel:28} {m['group']:12} {m['sloc']:6}")
    for g, n in s["groups"].items():
        line = f" (budget {s['budget']['sdk_c_cpp']})" if g == "sdk" else ""
        print(f"total {g:22} {n:6}{line}")
    for k, n in s["python"].items():
        line = f" (budget {s['budget']['python_host']})" if k.startswith("host (") else ""
        print(f"python {k:21} {n:6}{line}")
    if a.json:
        a.json.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
