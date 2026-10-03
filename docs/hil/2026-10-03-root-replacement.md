# HIL 2026-10-03: root replacement from a ledger backup (issue #5)

Bench: S3 root (`/dev/cu.usbmodem1101`), leaves XIAO C6 (`usbmodem1201`), C3 (`usbmodem1301`), XIAO C6 (`usbmodem3`),
ESP-IDF v6.0.3, macOS Host (uvicorn on a Unix socket). Firmware: `firmware/hil_node` of feat/transfer-ticket 427c9d3
(issue5/ledger-backup merged), written with `scripts/hil.sh update` (identity and membership kept).

## Run

1. Host started against the old root (term 15, PREAPPROVED, 14 ledger records incl. 2 REVOKED entries). The Host pulled
   the first backup 18 s after the session came up (two BUSY answers while the leaves re-attached after the root's
   restart): sequence 1, 14 records.
2. Host stopped; the S3 was erased (`hil.sh flash root`) and provisioned as the replacement root on the board's own key
   (`hil.py provision root --replacement --first-term 20`: delegation generation 2). `hil.py handover --term 20`: the
   fleet's RootHandover old -> new (308 B).
3. Host started: `another root claims domain ... the bridge stays down` (ROOT_MISMATCH), as specified.
4. `hil.py restore`: LEDGER_RESTORE of sequence 1 -> FINAL APPLIED "ledger of sequence 1 restored (14 records)" in 14 s.
   One USB session change interrupted it after step 1 of 16; the Host started it again by itself (the root clears its
   traces) and it completed. The Host then bound the domain to the new root ("the root changed by a completed
   ROOT_HANDOVER"). GET /v1/nodes listed the same 10 devices with their states (8 ACTIVE, 2 REVOKED).
5. Each leaf: `hil.py install --port P` (RootHandover, control 31: APPLIED) and `join transfer`.
   - C3: APPLIED; REACHABLE at term 20, membership generation 2, no new ticket or approval.
   - XIAO C6 (`usbmodem3`): restarted once during the first attempt (cause not identified); the stored handover survived
     the restart and a second `join transfer` was APPLIED; REACHABLE at term 20.
   - XIAO C6 (`usbmodem1201`): first `join transfer` EXPIRED; this board had ~27 % TX failures and was ISOLATED already
     before the root was replaced. The second attempt reached REACHABLE at term 20.
6. Host send to all three leaves: RECEIVED with END_RECEIVED(END_VERIFIED). The Host kept pulling backups from the new
   root (sequences 2, 3, 4 after the members' changes).

## Not verified here

- The cause of the `usbmodem3` restart and of the repeated USB session changes (REPLACED) right after a Host start.
- Restore after a power cut in the middle (covered in sim only: 24-point cut matrix in test_lifecycle).
- Transfer between two networks (needs a second root board).
