"""The records of one session: ndjson files (laptop UTC time on every line) and summary.csv. Written by one thread from a
bounded queue, so the UI and the event loop never wait for the disk; a failing disk becomes a warning on the page."""

from __future__ import annotations

import csv
import io
import json
import queue
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FILES = ("telemetry", "ping", "display", "events")
SUMMARY_COLUMNS = ("utc", "name", "device", "depth", "parent", "rssi_dbm", "telemetry_loss_pct", "ping_sent",
                   "ping_alive", "ping_lost", "ping_notsent", "ping_rtt_median_ms", "last_seen_age_s")
QUEUE_MAX = 20000


def utc_text(when: datetime | None = None) -> str:
    return (when or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def session_dir(base: Path, now: datetime | None = None) -> Path:
    return base / (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


class Recorder:
    def __init__(self, directory: Path, on_warning: Callable[[str], None] | None = None) -> None:
        self.directory = directory
        self.warning: str | None = None
        self.dropped = 0
        self.written = 0
        self._on_warning = on_warning
        self._q: queue.Queue[tuple[str, str] | None] = queue.Queue(QUEUE_MAX)
        self._handles: dict[str, io.TextIOWrapper] = {}
        self._thread = threading.Thread(target=self._run, name="fieldview-recorder", daemon=True)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._warn(f"cannot create {directory}: {exc}")
        self._thread.start()

    # ---- producers (any thread / the event loop; never blocks) -------------------------------------------------
    def log(self, stream: str, record: dict[str, Any]) -> None:
        """One ndjson line to <stream>.ndjson with the laptop's UTC time as "t"."""
        line = json.dumps({"t": utc_text(), **record}, separators=(",", ":"), ensure_ascii=False)
        self._put(f"{stream}.ndjson", line)

    def summary(self, rows: list[dict[str, Any]]) -> None:
        buf = io.StringIO()
        w = csv.DictWriter(buf, SUMMARY_COLUMNS, extrasaction="ignore", lineterminator="\n")
        for row in rows:
            w.writerow({k: ("" if row.get(k) is None else row[k]) for k in SUMMARY_COLUMNS})
        self._put("summary.csv", buf.getvalue().rstrip("\n"))

    def _put(self, name: str, text: str) -> None:
        try:
            self._q.put_nowait((name, text))
        except queue.Full:
            self.dropped += 1
            self._warn(f"the record queue is full: {self.dropped} lines dropped (the disk is too slow)")

    def close(self, timeout: float = 5.0) -> None:
        try:
            self._q.put(None, timeout=timeout)
        except queue.Full:
            pass
        self._thread.join(timeout)

    # ---- the writer ----------------------------------------------------------------------------------------------
    def _warn(self, text: str) -> None:
        self.warning = text
        if self._on_warning is not None:
            try:
                self._on_warning(text)
            except Exception:  # the warning channel must never break the recorder
                pass

    def _open(self, name: str) -> io.TextIOWrapper:
        h = self._handles.get(name)
        if h is None:
            path = self.directory / name
            fresh = name == "summary.csv" and not path.exists()
            h = path.open("a", encoding="utf-8", newline="")
            if fresh:
                h.write(",".join(SUMMARY_COLUMNS) + "\n")
            self._handles[name] = h
        return h

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                break
            name, text = item
            try:
                h = self._open(name)
                h.write(text + "\n")
                h.flush()
                self.written += 1
                if self.warning and self.warning.startswith("cannot write"):
                    self.warning = None  # the disk came back
            except (OSError, ValueError) as exc:
                self._handles.pop(name, None)
                self._warn(f"cannot write {name}: {exc}")
        for h in self._handles.values():
            try:
                h.close()
            except OSError:
                pass
        self._handles.clear()
