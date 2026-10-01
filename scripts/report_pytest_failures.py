#!/usr/bin/env python3
"""Expose bounded pytest failure details as GitHub annotations; the pytest step remains the gate."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def escape(text: str, *, property_value: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if property_value else text


def main(path: Path) -> None:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"::warning::{escape(f'pytest failure report unavailable: {exc}')}")
        return
    reported = 0
    for case in root.iter("testcase"):
        for detail in case:
            if detail.tag not in {"failure", "error"}:
                continue
            title = escape(f"{case.get('classname', '')}.{case.get('name', '')}"[:200],
                           property_value=True)
            message = detail.text or detail.get("message", "pytest failed")
            print(f"::error title={title}::{escape(message[-6000:])}")
            reported += 1
            if reported == 10:
                return


if __name__ == "__main__":
    main(Path(sys.argv[1]))
