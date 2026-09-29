PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=1000;
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE principals (
 id TEXT PRIMARY KEY, token_hash BLOB NOT NULL CHECK(length(token_hash)=32),
 permissions TEXT NOT NULL CHECK(json_valid(permissions)), enabled INTEGER NOT NULL CHECK(enabled IN(0,1))
) STRICT;
CREATE TABLE client_epochs (
 id BLOB PRIMARY KEY CHECK(length(id)=16), principal TEXT NOT NULL REFERENCES principals(id),
 state TEXT NOT NULL CHECK(state IN('OPEN','CLOSED')), created_utc_ms INTEGER,
 closed_utc_ms INTEGER, UNIQUE(id,principal)
) STRICT;
CREATE TABLE domains (
 id BLOB PRIMARY KEY CHECK(length(id)=16), root_device BLOB CHECK(length(root_device)=32),
 policy_revision INTEGER NOT NULL DEFAULT 0 CHECK(policy_revision>=0),
 delegation_generation INTEGER NOT NULL DEFAULT 0 CHECK(delegation_generation>=0)
) STRICT;
CREATE TABLE nodes (
 domain BLOB NOT NULL REFERENCES domains(id), device BLOB NOT NULL CHECK(length(device)=32),
 assignment_generation INTEGER NOT NULL CHECK(assignment_generation>=0),
 membership_generation INTEGER NOT NULL CHECK(membership_generation>=0),
 membership TEXT NOT NULL, connectivity TEXT NOT NULL,
 short_address INTEGER CHECK(short_address BETWEEN 1 AND 65534),
 confirmed INTEGER NOT NULL DEFAULT 0 CHECK(confirmed IN(0,1)),
 snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json)),
 PRIMARY KEY(domain,device)
) STRICT;
CREATE TABLE operations (
 id BLOB PRIMARY KEY CHECK(length(id)=16), principal TEXT NOT NULL REFERENCES principals(id),
 domain BLOB NOT NULL REFERENCES domains(id), type TEXT NOT NULL,
 client_epoch BLOB NOT NULL REFERENCES client_epochs(id), idempotency_key TEXT NOT NULL,
 request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
 message_id BLOB CHECK(length(message_id)=16), target_device BLOB CHECK(length(target_device)=32),
 request_json TEXT NOT NULL CHECK(json_valid(request_json)), payload BLOB,
 state TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT 'PENDING',
 expiry_utc_ms INTEGER, created_utc_ms INTEGER, evidence_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(evidence_json)),
 superseded_by BLOB REFERENCES operations(id),
 UNIQUE(principal,domain,type,client_epoch,idempotency_key),
 FOREIGN KEY(client_epoch,principal) REFERENCES client_epochs(id,principal)
) STRICT;
CREATE TABLE outbox (
 operation BLOB PRIMARY KEY REFERENCES operations(id), state TEXT NOT NULL,
 adapter_incarnation BLOB, external_write_possible INTEGER NOT NULL DEFAULT 0 CHECK(external_write_possible IN(0,1)),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0), next_attempt_utc_ms INTEGER
) STRICT;
CREATE TABLE inbox (
 domain BLOB NOT NULL REFERENCES domains(id), origin BLOB NOT NULL CHECK(length(origin)=32),
 assignment_generation INTEGER NOT NULL CHECK(assignment_generation>=0),
 message_id BLOB NOT NULL CHECK(length(message_id)=16), intent_hash BLOB NOT NULL CHECK(length(intent_hash)=32),
 payload BLOB NOT NULL, assurance_json TEXT NOT NULL CHECK(json_valid(assurance_json)),
 committed_utc_ms INTEGER,
 PRIMARY KEY(domain,origin,assignment_generation,message_id)
) STRICT;
CREATE TABLE events (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, domain BLOB NOT NULL REFERENCES domains(id),
 kind TEXT NOT NULL, operation BLOB REFERENCES operations(id),
 origin BLOB CHECK(length(origin)=32), message_id BLOB CHECK(length(message_id)=16),
 critical INTEGER NOT NULL CHECK(critical IN(0,1)),
 payload_json TEXT NOT NULL CHECK(json_valid(payload_json)), created_utc_ms INTEGER
) STRICT;
CREATE INDEX events_domain_seq ON events(domain,sequence);
CREATE TABLE consumers (
 principal TEXT NOT NULL REFERENCES principals(id), name TEXT NOT NULL,
 domain BLOB NOT NULL REFERENCES domains(id), journal_id BLOB NOT NULL CHECK(length(journal_id)=16),
 ack_sequence INTEGER NOT NULL CHECK(ack_sequence>=0), lease_expires_utc_ms INTEGER,
 PRIMARY KEY(principal,name,domain)
) STRICT;
CREATE TABLE lifecycle_requests (
 id BLOB PRIMARY KEY CHECK(length(id)=16), domain BLOB NOT NULL REFERENCES domains(id),
 device BLOB NOT NULL CHECK(length(device)=32), kind TEXT NOT NULL,
 state TEXT NOT NULL, expected_revision INTEGER NOT NULL CHECK(expected_revision>=0),
 signed_object BLOB, object_hash BLOB CHECK(length(object_hash)=32),
 evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json))
) STRICT;
CREATE TABLE health_faults (
 code TEXT PRIMARY KEY, active INTEGER NOT NULL CHECK(active IN(0,1)),
 first_seen_utc_ms INTEGER, last_seen_utc_ms INTEGER,
 detail_json TEXT NOT NULL CHECK(json_valid(detail_json))
) STRICT;

-- Spec0.2 additions. Schema definition only; existing deployment migration is additive.
CREATE TABLE node_power (
 domain BLOB NOT NULL, device BLOB NOT NULL,
 policy_revision INTEGER NOT NULL CHECK(policy_revision>=0),
 mode TEXT NOT NULL CHECK(mode IN('ALWAYS_RX','WINDOWED_RX','REPORT_ONLY')),
 policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
 snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json)),
 PRIMARY KEY(domain,device), FOREIGN KEY(domain,device) REFERENCES nodes(domain,device)
) STRICT;
CREATE TABLE group_targets (
 operation BLOB NOT NULL REFERENCES operations(id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 63),
 snapshot_token BLOB NOT NULL CHECK(length(snapshot_token)=16),
 snapshot_hash BLOB NOT NULL CHECK(length(snapshot_hash)=32),
 device BLOB NOT NULL CHECK(length(device)=32),
 assignment_generation INTEGER NOT NULL CHECK(assignment_generation>=0),
 membership_generation INTEGER NOT NULL CHECK(membership_generation>=0),
 message_id BLOB CHECK(length(message_id)=16),
 phase TEXT NOT NULL CHECK(phase IN('WAIT_ROUTE','WAIT_AUTH','WAIT_WAKE','READY','SENDING','WAIT_RECEIPT','FINAL')),
 outcome TEXT NOT NULL CHECK(outcome IN('PENDING','SUBMITTED','RECEIVED','APPLIED','REJECTED','EXPIRED','CANCELLED_NOT_SENT','INDETERMINATE','SUPERSEDED')),
 evidence_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(evidence_json)),
 PRIMARY KEY(operation,position), UNIQUE(operation,device)
) STRICT;
