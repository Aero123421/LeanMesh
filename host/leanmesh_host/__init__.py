"""LeanMesh Host: one FastAPI process, SQLite persistence, exclusive authenticated serial to the root.

Threads (docs/11 §2): event loop (HTTP), storage thread (the only sqlite connection), serial I/O
thread (the only owner of the port), crypto executor (native EDHOC binding). No ORM, no broker.
"""

SPEC_VERSION = "0.2"
