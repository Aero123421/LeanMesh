"""K06: the first-party core carries no application vocabulary (docs/14, AGENTS.md).

KGuard's words, Cloud URLs, fixed identifiers and display colours belong to the integration, never to the SDK core, the
public API, the wire/storage specs or the Host. This scans exactly those trees. It is a search, not a proof of
absence of meaning: a domain concept under a neutral name would pass, which is what review is for.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
# The first-party trees that must stay application-neutral (tests, docs, examples, tools and the KG integration notes are not).
SCANNED = ["src", "api", "protocol", "db", "components", "firmware", "cmake", "host/leanmesh_host", "config"]
SUFFIXES = {".c", ".h", ".cpp", ".hpp", ".cmake", ".txt", ".py", ".json", ".cddl", ".sql", ".csv", ".service", ".example",
            "Kconfig", ".defaults"}
FORBIDDEN = [
    ("KG word", re.compile(r"\bKG\b|\bKGuard\b|\bkguard\b", re.I)),
    ("KG product parts", re.compile(r"sitecore|edge-go|KG-WIRE|displaylink", re.I)),
    ("Pico display", re.compile(r"\bPico\b")),
    ("toilet vocabulary", re.compile(r"toilet|restroom|washroom|トイレ|個室|表示盤")),
    ("KG binding generation", re.compile(r"\bbinding_epoch\b")),
    ("Cloud URL or token", re.compile(r"https?://|\bcloud[_ -]?(token|url|api)\b|クラウド", re.I)),
]
# URLs that are part of a specification's own identity, not a service the SDK talks to.
ALLOWED_URL = re.compile(r"https?://(localhost|json-schema\.org|www\.w3\.org|spdx\.org|datatracker\.ietf\.org|"
                         r"github\.com/espressif|github\.com/vpetrigo)")


def scan(text: str) -> list[tuple[str, str]]:
    hits = []
    for name, rx in FORBIDDEN:
        for m in rx.finditer(text):
            if name.startswith("Cloud") and ALLOWED_URL.match(m.group(0) + text[m.end():m.end() + 60]):
                continue
            hits.append((name, m.group(0)))
    return hits


def first_party_files() -> list[Path]:
    out = []
    for d in SCANNED:
        base = REPO / d
        if not base.exists():
            continue
        for f in base.rglob("*"):
            # managed_components: third-party ESP-IDF components the component manager downloads (gitignored)
            if f.is_file() and "__pycache__" not in f.parts and "managed_components" not in f.parts and (
                    f.suffix in SUFFIXES or f.name in SUFFIXES
                    or f.name == "Kconfig"):
                out.append(f)
    return out


@pytest.mark.scenario("K06")
def test_first_party_core_has_no_application_vocabulary() -> None:
    files = first_party_files()
    assert len(files) > 200  # the scan really covers the tree (an empty glob would pass trivially)
    found = []
    for f in files:
        for name, word in scan(f.read_text(errors="replace")):
            found.append(f"{f.relative_to(REPO)}: {name}: {word!r}")
    assert not found, "application vocabulary in the SDK core:\n" + "\n".join(found[:30])


@pytest.mark.scenario("K06")
def test_the_scan_itself_catches_what_it_is_for() -> None:
    assert scan("// KGuard toilet display on the Pico via https://cloud.example.com/api")
    assert scan("uint64_t binding_epoch;")
    assert scan("KG-WIRE v2 codec")
    assert not scan("// install the key group; picosecond timer; https://json-schema.org/draft/2020-12/schema")
