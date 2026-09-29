#!/usr/bin/env python3
"""Scenario coverage map (docs/IMPLEMENTATION.md §9, decision D11): tests/scenarios.json ids -> the
tests that reference them. A STATIC mapping of references, not an execution result and never a product
pass: scenarios.json / traceability.csv / capability-manifest.json are read, never written.

  scripts/scenario_coverage.py [--out-dir DIR] [--results-junit FILE] [--caps-json FILE]

References are recognised only in these positions (so prose never counts):
  C++    LM_TEST("<ID>[ /,]<ID>... rest")     leading id tokens of the test name (suffix -sim/-style ok)
  pytest @pytest.mark.scenario("<ID>", ...)   every argument
Ids of other namespaces used as prefixes (slice S11..S20 and S1..S9, task T01..T28, SEC-*) are not scenario
references. Any other unknown id is an ERROR and the script exits 1 (typo or a deleted scenario).
Evidence classes: SIM (native test that builds a SimNode/World, or an E2E test against meshsim),
NATIVE_UNIT (native test without a simulated network), HOST (pytest without meshsim).
Statuses: NOT_RUN_HARDWARE (required level HARDWARE or in the §9 hardware-only list; sim evidence, if any,
is listed as 'sim'), COVERED_SOFTWARE_ONLY, NO_SOFTWARE_EVIDENCE, BUILD_REPORT (B01, from budget-report.json).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ID = re.compile(r"(?:POWER-[A-Za-z-]+|RF-[a-z0-9]+-[a-z0-9]+|[A-Z]{1,2}\d{2})(?![A-Za-z0-9])")
# Namespaces that look like scenario ids but are slices (S1..S20), tasks (T01..T28) or review ids (SEC-x).
FOREIGN = re.compile(r"(?:S\d(?!\d)|S1[1-9]|S20|T\d{2}|SEC-)")  # slices (S01..S10 are scenarios), tasks, review ids
SUFFIX = re.compile(r"-(?:sim|style|unit|codec)\b")
LM_TEST = re.compile(r'LM_TEST\("([^"]*)"\)')
MARK = re.compile(r"pytest\.mark\.scenario\(([^)]*)\)")
# IMPLEMENTATION.md §9: hardware-only scenarios (sim versions stay labelled 'sim').
HW_ONLY = ("RF-", "C01", "S03", "S08", "H03", "O01", "O03", "K01", "K02", "K03", "K04", "K05", "M07",
           "L01", "LP02", "LP19", "ME01", "ME02", "ME03", "ME06", "ME07", "ME08", "POWER-")
HW_PARTS = ("R01", "R02", "R06", "R07")  # physical parts remain NOT_RUN even with sim evidence
# capability-manifest feature -> scenarios that exercise it in software (judgement, not from the spec).
FEATURE_SCENARIOS = {
    "SMALL_MESSAGE": ["D01", "D03", "D04", "D06"], "OBJECT_4K": ["D07", "D08", "D09"],
    "GROUP_FANOUT_V2": ["GS01", "GS02", "GS03", "GS07", "GS10", "D11", "D12"],
    "POWER_REPORT_ONLY": ["LP03", "LP04", "LP05"], "POWER_WINDOWED_RX": ["LP13", "LP14", "LP17"],
    "RAM_SESSION_RETAIN": ["LP08", "LP09"], "AUTO_CHANNEL": ["C02", "C03", "C06", "C07", "C12"],
    "SIGNED_TRANSFER": ["M03", "M04"], "COMMISSIONING_WINDOW": ["LC01", "LC03"],
    "ROOT_HANDOVER": ["LC08", "LC10"], "RTC_SECURE_RESUME_RESERVED": ["LP20"],
}


def git_head() -> str:
    def g(*a):
        return subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True).stdout.strip()
    return g("rev-parse", "--short", "HEAD") + (" (dirty)" if g("status", "--porcelain") else "")


def leading_ids(name: str) -> list[str]:
    """Scenario-shaped tokens at the start of a test name (unknown ones are returned; the caller errors)."""
    ids, rest = [], name.strip()
    while rest and not FOREIGN.match(rest):
        m = ID.match(rest)
        if not m:
            break
        ids.append(m.group(0))
        rest = SUFFIX.sub("", rest[m.end():], count=1) if SUFFIX.match(rest[m.end():]) else rest[m.end():]
        sep = re.match(r"[ /,]+", rest)
        if not sep:
            break
        rest = rest[sep.end():]
    return ids


def is_foreign_first(name: str) -> bool:
    return bool(FOREIGN.match(name.strip()))


def scan_cpp(refs, errors):
    for f in sorted((REPO / "tests/native").glob("*.cpp")):
        text = f.read_text(errors="replace")
        marks = list(LM_TEST.finditer(text))
        for i, m in enumerate(marks):
            name = m.group(1)
            line = text.count("\n", 0, m.start()) + 1
            if is_foreign_first(name):
                continue
            body = text[m.end(): marks[i + 1].start() if i + 1 < len(marks) else len(text)]
            cls = "SIM" if re.search(r"\b\w*(Net|Network|SimNode|World)\b|\bsim::", body) or re.search(r"\bsim\b", name) else "NATIVE_UNIT"
            for sid in leading_ids(name):
                refs.append((sid, cls, name, f"{f.relative_to(REPO)}:{line}"))


def scan_py(refs, errors):
    for f in sorted((REPO / "host/tests").rglob("*.py")):
        text = f.read_text(errors="replace")
        sim = "e2e" in f.parts or "meshsim" in text
        for m in MARK.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            after = text[m.end():]
            fn = re.search(r"def (test_\w+)", after)
            name = fn.group(1) if fn else "(module/class mark)"
            for arg in re.findall(r"""["']([^"']+)["']""", m.group(1)):
                if is_foreign_first(arg):
                    continue
                refs.append((arg, "SIM" if sim else "HOST", name, f"{f.relative_to(REPO)}:{line}"))


def sim_caps(meshsim: Path) -> dict:
    """Implemented/enabled feature names as a simulated root node reports them (lm_get_capabilities, via `diag`)."""
    import subprocess
    cmds = "start 0\ndiag 0\nquit\n"
    r = subprocess.run([str(meshsim), "--nodes", "1", "--topology", "chain", "--clock", "virtual"], input=cmds,
                       capture_output=True, text=True, timeout=60, check=True)
    rows = [json.loads(line) for line in r.stdout.splitlines() if line.startswith("{")]
    diag = next(x for x in rows if "features" in x)
    return {"implemented": [f["name"] for f in diag["features"] if f["implemented"]],
            "enabled": [f["name"] for f in diag["features"] if f["enabled"]],
            "source": "meshsim diag 0 (simulated root node; a bench fact, not a device measurement)"}


def executed_from_junit(path: Path) -> set[str]:
    ok = set()
    for tc in ET.parse(path).getroot().iter("testcase"):
        if not any(c.tag in ("failure", "error", "skipped") for c in tc):
            ok.add(tc.get("name", "").split("[")[0])
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--results-junit", type=Path, help="pytest --junitxml: pytest references are marked executed")
    ap.add_argument("--caps-json", type=Path, help='{"implemented":[names],"enabled":[names]} from lm_get_capabilities')
    ap.add_argument("--meshsim", type=Path, help="native meshsim binary: asks a simulated root node (diag 0) for the capability facts")
    a = ap.parse_args()

    scen = {s["id"]: s for s in json.loads((REPO / "tests/scenarios.json").read_text())["scenarios"]}
    refs: list[tuple[str, str, str, str]] = []
    errors: list[str] = []
    scan_cpp(refs, errors)
    scan_py(refs, errors)
    for sid, _, name, where in refs:
        if sid not in scen:
            errors.append(f"{where}: unknown scenario id '{sid}' (test '{name}')")
    if errors:
        print("ERROR: scenario ids referenced by tests that tests/scenarios.json does not define:", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
    done = executed_from_junit(a.results_junit) if a.results_junit else None

    budget = REPO / "build-records/budget-report.json"
    b01 = None
    if budget.is_file():
        b01 = json.loads(budget.read_text()).get("b01")
    rows = []
    for sid in sorted(scen):
        s = scen[sid]
        ev = [{"class": c, "test": n, "at": w,
               **({"executed": n in done} if done is not None and ".py:" in w else {})}
              for i, c, n, w in refs if i == sid]
        hw = s["level"] == "HARDWARE" or sid.startswith(HW_ONLY) or sid in HW_PARTS
        if sid == "B01":
            status = "BUILD_REPORT" if b01 and b01.get("all_built") else "NO_SOFTWARE_EVIDENCE"
        elif hw:
            status = "NOT_RUN_HARDWARE"
        else:
            status = "COVERED_SOFTWARE_ONLY" if ev else "NO_SOFTWARE_EVIDENCE"
        rows.append({"id": sid, "title": s["title"], "required_level": s["level"], "status": status,
                     "hardware_evidence": "NOT_RUN" if hw else None,
                     "software_evidence": sorted(ev, key=lambda e: (e["class"], e["at"])),
                     "sim_only_label": "sim" if hw and ev else None})
    counts: dict[str, int] = {}
    levels: dict[str, dict[str, int]] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        lv = levels.setdefault(r["required_level"], {})
        lv[r["status"]] = lv.get(r["status"], 0) + 1
    caps = json.loads(a.caps_json.read_text()) if a.caps_json else (sim_caps(a.meshsim) if a.meshsim else None)
    features = []
    for f in json.loads((REPO / "config/capability-manifest.json").read_text())["features"]:
        ids = FEATURE_SCENARIOS.get(f["name"], [])
        sw = [r for r in rows if r["id"] in ids]
        features.append({
            "name": f["name"], "scenarios": ids,
            "implemented": ("unknown - not queried" if caps is None else f["name"] in caps.get("implemented", [])),
            "software_evidence_for": sum(1 for r in sw if r["software_evidence"]), "of": len(sw),
            "host_tested": bool(sw) and all(r["software_evidence"] for r in sw),
            "hardware_tested": False, "qualified": False})
    out = {"head": git_head(), "mode": "static reference map (not an execution result)"
           if done is None else "static reference map + pytest junit results for pytest tests",
           "counts": dict(sorted(counts.items())), "by_required_level": {k: dict(sorted(v.items())) for k, v in sorted(levels.items())},
           "references": len(refs), "errors": errors, "scenarios": rows, "features": features}
    summary = f"{len(rows)} scenarios, {len(refs)} references: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(summary)
    if a.out_dir:
        a.out_dir.mkdir(parents=True, exist_ok=True)
        (a.out_dir / "scenario-coverage.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
        (a.out_dir / "scenario-coverage.md").write_text(markdown(out))
    return 1 if errors else 0


def markdown(o: dict) -> str:
    L = ["# Scenario coverage (generated by scripts/scenario_coverage.py)", "",
         f"Commit {o['head']}. **{o['mode']}.** Software evidence never replaces the product scenarios: every hardware",
         "scenario stays NOT_RUN (decision D11, docs/18 §7). Spec files are unchanged.", "", "## Counts", "",
         "| status | scenarios |", "|---|---:|"]
    L += [f"| {k} | {v} |" for k, v in o["counts"].items()]
    L += ["", "| required level | " + " | ".join(sorted({s for v in o["by_required_level"].values() for s in v})) + " |"]
    sts = sorted({s for v in o["by_required_level"].values() for s in v})
    L += ["|---|" + "---:|" * len(sts)]
    L += [f"| {lv} | " + " | ".join(str(v.get(s, 0)) for s in sts) + " |" for lv, v in o["by_required_level"].items()]
    gaps = [r for r in o["scenarios"] if r["status"] == "NO_SOFTWARE_EVIDENCE"]
    L += ["", "## Gaps: software-level scenarios with no referencing test", ""]
    L += [f"- {r['id']} ({r['required_level']}) {r['title']}" for r in gaps] or ["- none"]
    L += ["", "## Hardware scenarios with sim evidence only (labelled sim)", ""]
    L += [f"- {r['id']} {r['title']}: " + ", ".join(sorted({e['class'] for e in r['software_evidence']}))
          for r in o["scenarios"] if r["sim_only_label"]] or ["- none"]
    L += ["", "## Capability features (docs/18 §6; hardware_tested and qualified are false everywhere)", "",
          "| feature | implemented | host_tested | software evidence | scenarios |", "|---|---|---|---|---|"]
    L += [f"| {f['name']} | {f['implemented']} | {f['host_tested']} | {f['software_evidence_for']}/{f['of']} | {', '.join(f['scenarios'])} |"
          for f in o["features"]]
    L += ["", "## Per scenario", "", "| id | level | status | evidence |", "|---|---|---|---|"]
    for r in o["scenarios"]:
        ev = "; ".join(f"{e['class']} {e['at']}" for e in r["software_evidence"][:3])
        more = len(r["software_evidence"]) - 3
        L.append(f"| {r['id']} | {r['required_level']} | {r['status']} | {ev}{f' (+{more})' if more > 0 else ''} |")
    if o["errors"]:
        L += ["", "## ERRORS", ""] + [f"- {e}" for e in o["errors"]]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())
