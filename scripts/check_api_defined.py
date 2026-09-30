#!/usr/bin/env python3
"""Public C API completeness (api/leanmesh.h).

1. Every `lm_*` function declared in the header has a definition in the native build (nm of the built static
   libraries: lm_sdk + lm_sim), and a definition in the sources the device build compiles (src/** except src/port/sim and src/hostnative).
2. The evidence bits / phases of the header equal what the Host maps (host/leanmesh_host/bridge/mapping.py) and the
   openapi Operation states.

Usage: check_api_defined.py [--native-build DIR]   (default $LEANMESH_NATIVE_BUILD or ~/.cache/leanmesh/native)
Fails (exit 1) on any missing definition; there is no allowlist.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DECL = re.compile(r"^\s*lm_status_t\s+(lm_[a-z0-9_]+)\s*\(", re.M)


def declared():
    text = re.sub(r"/\*.*?\*/", "", (ROOT / "api/leanmesh.h").read_text(), flags=re.S)
    return sorted(set(DECL.findall(text)))


def native_symbols(build: Path):
    libs = sorted(build.glob("liblm_sdk.a")) + sorted(build.glob("liblm_sim.a"))
    if len(libs) != 2:
        sys.exit(f"FAIL: liblm_sdk.a / liblm_sim.a not found in {build} (build first)")
    out = subprocess.run(["nm", "-g", "--defined-only", *map(str, libs)], check=True, capture_output=True, text=True).stdout
    return {ln.split()[-1] for ln in out.splitlines() if re.match(r"^[0-9a-f]+ [TW] ", ln)}


def source_defined():
    found = set()
    pat = re.compile(r"^(?:extern \"C\" )?lm_status_t\s+(lm_[a-z0-9_]+)\s*\(", re.M)
    for p in (ROOT / "src").rglob("*.cpp"):
        rel = p.relative_to(ROOT / "src").parts
        if rel[:2] == ("port", "sim") or rel[0] == "hostnative":
            continue  # a definition in the simulator or the Host helper does not make the function part of the device SDK
        found.update(pat.findall(p.read_text()))
    return found


def header_defines(prefix):
    text = (ROOT / "api/leanmesh.h").read_text()
    return {m.group(1): int(m.group(2)) for m in re.finditer(rf"#define\s+({prefix}\w*)\s+\(UINT32_C\(1\)\s*<<\s*(\d+)u\)", text)}


def check_evidence(errors):
    ev = header_defines("LM_EVIDENCE_")
    mapping = (ROOT / "host/leanmesh_host/bridge/mapping.py").read_text()
    block = mapping[mapping.index("EVIDENCE_BITS = ("):]
    host = [int(m.group(1)) for m in re.finditer(r"\(1 << (\d+),", block[: block.index("\n)")])]
    if sorted(ev.values()) != host or len(set(ev.values())) != len(ev):
        errors.append(f"LM_EVIDENCE_* bits {sorted(ev.values())} != Host EVIDENCE_BITS {host}")
    header = (ROOT / "api/leanmesh.h").read_text()
    phases = re.search(r"LM_PHASE_PENDING=0, LM_PHASE_SENDING=1, LM_PHASE_WAITING_RECEIPT=2, LM_PHASE_FINAL=3", header)
    api = json.loads((ROOT / "api/openapi.json").read_text())
    states = api["components"]["schemas"]["Operation"]["properties"]["state"]["enum"]
    if not phases or states[1:5] != ["PENDING", "SENDING", "WAITING_RECEIPT", "FINAL"]:
        errors.append(f"LM_PHASE_* != openapi Operation.state {states}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--native-build", default=os.environ.get("LEANMESH_NATIVE_BUILD", str(Path.home() / ".cache/leanmesh/native")))
    build = Path(ap.parse_args().native_build).expanduser()
    decl = declared()
    errors = []
    if len(decl) < 30:
        errors.append(f"header parse found only {len(decl)} functions")
    nat, src = native_symbols(build), source_defined()
    for f in decl:
        if f not in nat:
            errors.append(f"{f}: declared in api/leanmesh.h, no definition in the native build")
        if f not in src:
            errors.append(f"{f}: declared in api/leanmesh.h, no definition under src/")
    check_evidence(errors)
    for e in errors:
        print("FAIL:", e)
    print(f"{len(decl)} public functions checked, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
