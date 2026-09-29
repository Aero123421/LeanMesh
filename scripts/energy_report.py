"""Integrate an explicitly labelled current trace; never invent measurements.

CSV: time_s,voltage_v,current_ma[,phase]. All samples must be finite,
nonnegative and strictly increasing in time. Trapezoidal integration is an
approximation whose validity depends on the instrument's sampling bandwidth.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from typing import Any


def integrate(path: Path, *, max_gap_s: float) -> dict[str, Any]:
    if not math.isfinite(max_gap_s) or max_gap_s <= 0:
        raise ValueError("max_gap_s must be finite and positive")
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not {"time_s", "voltage_v", "current_ma"}.issubset(reader.fieldnames or []):
            raise ValueError("required CSV columns missing")
        samples = []
        for line, row in enumerate(reader, 2):
            try:
                t, v, i = (float(row[k]) for k in ("time_s", "voltage_v", "current_ma"))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"invalid numeric sample on line {line}") from exc
            if not all(math.isfinite(x) for x in (t, v, i)) or t < 0 or v <= 0 or i < 0:
                raise ValueError(f"nonfinite or invalid sign on line {line}")
            if samples:
                gap = t - samples[-1][0]
                if not 0 < gap <= max_gap_s:
                    raise ValueError(f"timestamp order/sample gap on line {line}")
            samples.append((t, v, i))
    if len(samples) < 2:
        raise ValueError("at least two samples required")
    current_integral = energy_j = 0.0
    for (ta, va, ia), (tb, vb, ib) in zip(samples, samples[1:]):
        dt = tb - ta
        current_integral += dt * (ia + ib) / 2
        energy_j += dt * (va * ia + vb * ib) / 2000
    seconds = samples[-1][0] - samples[0][0]
    return {"samples": len(samples), "duration_s": seconds,
            "charge_mah": current_integral / 3600,
            "energy_j": energy_j, "average_current_ma": current_integral / seconds,
            "peak_current_ma": max(x[2] for x in samples),
            "trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "integration": "trapezoidal; sample-bandwidth dependent"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--kind", required=True, choices=["SYNTHETIC", "MEASURED"])
    parser.add_argument("--max-gap-s", required=True, type=float)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = integrate(args.csv, max_gap_s=args.max_gap_s)
        result["trace_kind"] = args.kind
        result["battery_lifetime_guarantee"] = False
        if args.kind == "MEASURED":
            if args.metadata is None:
                raise ValueError("MEASURED requires --metadata with device/instrument provenance")
            meta = json.loads(args.metadata.read_text())
            required = ("status", "soc", "board", "firmware_sha256", "instrument", "trace_sha256")
            if any(not meta.get(k) for k in required) or meta["status"] != "MEASURED":
                raise ValueError("measurement provenance incomplete")
            if meta["trace_sha256"] != result["trace_sha256"]:
                raise ValueError("metadata trace hash does not match")
            result["metadata"] = meta
        encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8")
        else:
            print(encoded, end="")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
