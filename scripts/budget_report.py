#!/usr/bin/env python3
"""Budget report (docs/16): sizeof per profile, fixed RAM against the profile targets and
first-party SLOC per module. A report, not a gate: it exits non-zero only when it cannot measure.

  scripts/budget_report.py [--native-build DIR] [--idf-build DIR]... [--idf-root DIR] [--out-dir DIR]

--idf-root      a LEANMESH_BUILD_ROOT: every example_node[-RELAY|-ROOT]/<soc> in it is measured (all four SoCs
                give the per-SoC tables and the B01 build evidence). --out-dir writes budget-report.{json,md}
                (build-records/ is the committed copy). Targets are the ADR-002 revised ones (TARGETS below).
--crypto-log    output of `test_security "measure: worker stack"`; without it the test binary in --native-build runs.

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
import hashlib
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

# docs/16 budget sets. "sdk" = first-party C/C++ compiled into the firmware, split into core (src/core,
# security, store, capi), idf (src/port/idf), root (src/root) and serial (src/serial). Native-only ports,
# tools, tests and vendor sources are separate columns and never in the SDK denominator.
SLOC_MODULES = (
    ("src/core", "core", False),  # top-level core files only; subdirectories are listed below
    *((f"src/core/{m}", "core", True) for m in (
        "wire", "radio", "link", "member", "route", "delivery", "sched", "group", "channel",
        "power", "diag", "ota")),
    *((f"src/{m}", "core", True) for m in ("security", "store", "capi")),
    ("src/port/idf", "idf", True), ("src/root", "root", True), ("src/serial", "serial", True),
    ("src/port/sim", "native-only", True), ("src/hostnative", "native-only", True),
    ("tools", "tools", True), ("tests/native", "tests", True),
    ("third_party", "vendor", True),
)
SDK_PARTS = ("core", "idf", "root", "serial")
# Revised targets (decisions/ADR-002, docs/16 "実装時の改訂"); config/profiles.json still carries the
# original docs/16 RAM numbers and is a spec file, so the revised ones live here.
TARGETS = {"ram": {"leaf": 48 * 1024, "relay": 56 * 1024, "root": 160 * 1024},
           "flash": 256 * 1024, "flash_review": 320 * 1024, "sdk_sloc": 28000, "python_host": 6000,
           "crypto_peak": 24 * 1024}
SOCS = ("esp32s3", "esp32c3", "esp32c5", "esp32c6")
APPS = {"leaf": "example_node", "relay": "example_node-RELAY", "root": "example_node-ROOT"}
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
    groups["sdk (core+idf+root+serial)"] = sum(groups.get(g, 0) for g in SDK_PARTS)
    return {"modules": modules, "groups": groups, "python": py,
            "budget": {"sdk_c_cpp": TARGETS["sdk_sloc"], "python_host": TARGETS["python_host"]}}


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
            # The memory type holding .dram0.* is called DRAM (C3), DIRAM (S3, C6) or HP SRAM (C5): find it by its sections.
            dram = next((m["sections"] for m in mem.values() if ".dram0.bss" in m["sections"]), {})
            code = sum(m["sections"].get(".flash.text", {}).get("size", 0) for m in mem.values())
            data = sum(m["size"] for k, m in mem.items() if k.startswith("Flash")) - code
            info["static"] = {"dram_bss": dram.get(".dram0.bss", {}).get("size", 0),
                              "dram_data": dram.get(".dram0.data", {}).get("size", 0),
                              "flash_code": code, "flash_data": data}
        break
    size = build / "size.json"
    base = REPO / "build-records" / "T01-baseline-size.json"
    if size.is_file() and base.is_file() and info["target"]:
        raw = size.read_text()
        info["image_bytes"] = json.loads(raw[raw.index("\n{\n") + 1:]).get("total_size")
        base_targets = json.loads(base.read_text())["targets"]
        info["baseline_image_bytes"] = base_targets.get(info["target"], {}).get("image_total_bytes")
    return info


def constant(path: str, name: str) -> int:
    m = re.search(rf"\b{name}\s*=\s*(\d+)", (REPO / path).read_text())
    if not m:
        sys.exit(f"{path}: constant {name} not found")
    return int(m.group(1))


def fixed_ram(sizes: dict[str, dict[str, int]], builds: list[dict]) -> dict[str, dict]:
    """Fixed RAM per profile for one SoC (or the native estimate when `builds` is empty)."""
    owner = constant("src/port/idf/idf_owner.hpp", "k_stack_bytes")
    worker = constant("src/port/idf/idf_jobs.hpp", "k_stack_bytes")
    usb_stack = constant("src/serial/idf_serial.cpp", "k_task_stack_bytes")
    usb_ring = constant("src/serial/idf_serial.cpp", "k_rx_ring_bytes")
    res = {}
    for p in PROFILES:
        s = sizes[p]
        items = {"workspace (lm_context)": s["ctx"]}
        mapped = next((b for b in builds if b["profile"] == p and b["static"]), None)
        if mapped:
            st = mapped["static"]
            items["libleanmesh.a static DRAM (map)"] = st["dram_bss"] + st["dram_data"]
            basis = f"link map of {Path(mapped['build']).parent.name}/{mapped['target']}"
        else:
            items["owner task stack"] = owner
            items["worker task stack"] = worker
            items["radio (rx/done rings)"] = s["platform__radio"]
            if p == "root":
                items["USB serial adapter (RootUsb)"] = s["root__usb"]
                items["USB task stack + byte ring"] = usb_stack + usb_ring
            basis = "estimate (sizeof + stack/ring constants)"
        total = sum(items.values())
        res[p] = {"items": items, "total": total, "target": TARGETS["ram"][p], "basis": basis,
                  "verdict": "OK" if total <= TARGETS["ram"][p] else "OVER"}
    return res


def flash_verdict(diff: int | None) -> str:
    if diff is None:
        return "unknown"
    return "OK" if diff <= TARGETS["flash"] else \
        "OVER" if diff <= TARGETS["flash_review"] else "OVER-REVIEW-LINE"


def discover(root: Path) -> list[Path]:
    """<root>/example_node[-RELAY|-ROOT]/<soc> for every SoC that was built (has compile_commands.json)."""
    found = [root / app / soc for soc in SOCS for app in APPS.values()]
    return [d for d in found if (d / "compile_commands.json").is_file()]


def crypto_peak(log: Path | None, native: Path) -> dict:
    """Worker stack and PSA heap peak of one handshake, parsed from the native test's [measure] lines."""
    text = log.read_text() if log else ""
    source = str(log) if log else None
    exe = native / "tests" / "native" / "test_security"
    if not text and exe.is_file():
        r = subprocess.run([str(exe), "measure: worker stack and PSA heap peak"], capture_output=True, text=True)
        text, source = r.stdout, "tests/native/test_security (run now)"
    stack = re.search(r"\[measure\] worker stack peak[^:]*: (\d+) bytes", text)
    heap = re.search(r"\[measure\] PSA heap peak[^:]*: (\d+) bytes", text)
    if stack and heap:
        st, hp = int(stack.group(1)), int(heap.group(1))
        return {"basis": f"measured natively (x86-64 software model), {source}", "worker_stack": st,
                "psa_heap": hp, "total": st + hp}
    return {"basis": "recorded in ADR-002, not re-measured", "worker_stack": 4840, "psa_heap": 4992,
            "total": 4840 + 4992}


def b01(builds: list[dict]) -> dict:
    """4-target same-pin build evidence (scenario B01, build part only)."""
    pin = json.loads((REPO / "config/dependencies.json").read_text())["esp_idf"]["commit"]
    idf_path = Path(os.environ.get("IDF_PATH", str(Path.home() / "esp/esp-idf-v6.0.3")))
    head = subprocess.run(["git", "-C", str(idf_path), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    per = {}
    for soc in SOCS:
        have = {b["profile"]: b for b in builds if b["target"] == soc}
        gens = {b["profile"]: hashlib.sha256(g.read_bytes()).hexdigest()[:16] for b in have.values()
                for g in [Path(b["build"]) / "esp-idf/leanmesh/lm_generated/gen/registry.hpp"] if g.is_file()}
        per[soc] = {"built": sorted(have), "registry_hpp": gens}
    hashes = {h for v in per.values() for h in v["registry_hpp"].values()}
    return {"all_built": all("leaf" in v["built"] and "root" in v["built"] for v in per.values()),
            "idf_pin": pin, "idf_checkout": head or "unknown (IDF_PATH not a git tree)",
            "same_pin": head == pin, "per_soc": per, "generated_constants_identical": len(hashes) <= 1 and bool(hashes),
            "cannot_show": "that unsupported APIs return UNSUPPORTED instead of a fake success (review + tests do), "
                           "runtime heap peaks, or that the images run on the SoC"}


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


def head_info() -> dict:
    def g(*a):
        return subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True).stdout.strip()
    return {"head": g("rev-parse", "--short", "HEAD"), "dirty": bool(g("status", "--porcelain"))}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_native = os.environ.get("LEANMESH_NATIVE_BUILD",
                                    str(Path.home() / ".cache/leanmesh/native"))
    ap.add_argument("--native-build", type=Path, default=Path(default_native))
    ap.add_argument("--idf-build", type=Path, action="append", default=[])
    ap.add_argument("--idf-root", type=Path, help="a LEANMESH_BUILD_ROOT: every example_node[-RELAY|-ROOT]/<soc> in it")
    ap.add_argument("--crypto-log", type=Path, help="output of test_security 'measure: worker stack' (else run from --native-build)")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--out-dir", type=Path, help="write budget-report.json and budget-report.md here")
    a = ap.parse_args()

    idf_dirs = list(a.idf_build) + (discover(a.idf_root) if a.idf_root else [])
    report: dict = {"native": native_sizes(a.native_build), **head_info(), "command": " ".join(sys.argv)}
    builds = sorted((idf_build_info(b) for b in idf_dirs), key=lambda b: (b["target"] or "", b["profile"] or ""))
    if report["native"] is None and not builds:
        sys.exit(f"{a.native_build}: no lm_budget_probe_* libraries (build the native tree) "
                 "and no --idf-build/--idf-root given")
    report["tools"] = {"python": sys.version.split()[0], "gcc": subprocess.run(
        ["c++", "--version"], capture_output=True, text=True).stdout.splitlines()[0]}
    report["fixed_ram"] = {}
    if builds:
        report["idf"] = {"sizes": {}, "builds": builds}
        for soc in sorted({b["target"] for b in builds}):
            mine = [b for b in builds if b["target"] == soc]
            report["idf"]["sizes"][soc] = idf_sizes(Path(mine[0]["build"]))
            report["fixed_ram"][soc] = fixed_ram(report["idf"]["sizes"][soc], mine)
        for b in builds:
            d = b["image_bytes"] - b["baseline_image_bytes"] if b["image_bytes"] and b["baseline_image_bytes"] else None
            b["image_diff"], b["flash_verdict"] = d, flash_verdict(d)
        report["missing_socs"] = [s for s in SOCS if s not in report["idf"]["sizes"]]
        report["b01"] = b01(builds)
    if report["native"] is not None:
        report["fixed_ram"]["native-estimate"] = fixed_ram(report["native"], [])
    report["crypto"] = crypto_peak(a.crypto_log, a.native_build)
    report["crypto"]["verdict"] = "OK" if report["crypto"]["total"] <= TARGETS["crypto_peak"] else "OVER"
    report["sloc"] = sloc_report()
    report["sloc"]["verdict"] = "OK" if report["sloc"]["groups"]["sdk (core+idf+root+serial)"] <= TARGETS["sdk_sloc"] else "OVER"
    report["targets"] = TARGETS
    text = render(report, a)
    print(text)
    if a.json:
        a.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if a.out_dir:
        a.out_dir.mkdir(parents=True, exist_ok=True)
        (a.out_dir / "budget-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (a.out_dir / "budget-report.md").write_text(text + "\n")
    return 0


def render(r: dict, a) -> str:
    """Markdown; tables only carry measured numbers or say 'unknown'."""
    T = TARGETS
    L = ["# LeanMesh budget report (docs/16 + ADR-002 revised targets; a report, not a gate)", "",
         f"Commit `{r['head']}`{' (working tree dirty)' if r['dirty'] else ''}; python {r['tools']['python']}, {r['tools']['gcc']}.",
         f"Command: `{r['command']}`", "",
         "Software measurements only: sizeof from the compiler, static DRAM from the link map, image diff against",
         "`build-records/T01-baseline-size.json`. No heap, stack, CPU or current was measured on a SoC.", ""]
    if r.get("missing_socs"):
        L += [f"**This run lacks builds for: {', '.join(r['missing_socs'])}.**", ""]
    L += ["## Fixed RAM (workspace + static DRAM of libleanmesh.a) vs revised targets", "",
          "| SoC | profile | fixed RAM B | target B | over B | verdict | basis |", "|---|---|---:|---:|---:|---|---|"]
    for soc, profs in r["fixed_ram"].items():
        for p in PROFILES:
            f = profs[p]
            L.append(f"| {soc} | {p.upper()} | {f['total']} | {f['target']} | {f['total'] - f['target']:+d} | {f['verdict']} | {f['basis']} |")
    L += ["", "## Flash: image minus empty IDF + ESP-NOW baseline (target 256 KiB, review line 320 KiB)", "",
          "| SoC | profile | image B | baseline B | diff B | verdict | libleanmesh.a DRAM bss+data B | flash code+data B |",
          "|---|---|---:|---:|---:|---|---:|---:|"]
    for b in r.get("idf", {}).get("builds", []):
        st = b["static"] or {}
        L.append(f"| {b['target']} | {(b['profile'] or '?').upper()} | {b['image_bytes']} | {b['baseline_image_bytes']} | "
                 f"{b['image_diff']} | {b['flash_verdict']} | {st.get('dram_bss', 0) + st.get('dram_data', 0) if st else 'n/a'} | "
                 f"{st.get('flash_code', 0) + st.get('flash_data', 0) if st else 'n/a'} |")
    c = r["crypto"]
    L += ["", "## Crypto peak (target <= 24 KiB, separate from fixed RAM)", "",
          f"worker stack {c['worker_stack']} B + PSA heap {c['psa_heap']} B = {c['total']} B ({c['verdict']}); {c['basis']}.", ""]
    s = r["sloc"]
    L += ["## First-party SLOC (non-blank, non-comment)", "", "| group | SLOC | budget |", "|---|---:|---|"]
    for g, n in s["groups"].items():
        bud = f"{T['sdk_sloc']} ({s['verdict']})" if g.startswith("sdk") else ""
        L.append(f"| {g} | {n} | {bud} |")
    for k, n in s["python"].items():
        L.append(f"| python {k} | {n} | {T['python_host'] if k.startswith('host (') else ''} |")
    L += ["", "| module | group | SLOC |", "|---|---|---:|"] + [f"| {k} | {m['group']} | {m['sloc']} |" for k, m in s["modules"].items()]
    if "b01" in r:
        b = r["b01"]
        L += ["", "## B01 build evidence (4 targets, one pin)", "",
              f"IDF pin {b['idf_pin']}; checkout {b['idf_checkout']}; same pin: {b['same_pin']}; "
              f"all four SoCs built LEAF and ROOT: {b['all_built']}; generated registry.hpp identical across builds: "
              f"{b['generated_constants_identical']}.", "", "| SoC | profiles built | registry.hpp hash |", "|---|---|---|"]
        L += [f"| {soc} | {', '.join(v['built']) or 'none'} | {', '.join(sorted(set(v['registry_hpp'].values()))) or 'n/a'} |"
              for soc, v in b["per_soc"].items()]
        L += ["", f"Cannot show: {b['cannot_show']}."]
    sizes = r["native"] or next(iter(r["idf"]["sizes"].values()))
    L += ["", "## sizeof per profile (" + ("native x86-64" if r["native"] else "SoC compiler") + ")", "",
          "| object | LEAF | RELAY | ROOT |", "|---|---:|---:|---:|"]
    L += [f"| {n.replace('__', '.')} | {sizes['leaf'].get(n, 0)} | {sizes['relay'].get(n, 0)} | {sizes['root'].get(n, 0)} |"
          for n in sorted(sizes["leaf"])]
    return "\n".join(L)


if __name__ == "__main__":
    sys.exit(main())
