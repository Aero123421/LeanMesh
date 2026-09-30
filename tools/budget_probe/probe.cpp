// Budget probe (docs/16 §2: object sizes are recorded with sizeof, not with hand arithmetic).
// Every line below defines one zero-filled array whose size is the measured object, so `nm -S` on
// the compiled object reports the compiler's figure for the profile the file was compiled with
// (LM_BUILD_PROFILE_LEAF / RELAY / ROOT). The file is never linked into a program;
// scripts/budget_report.py compiles and reads it (natively through the lm_budget_probe_* targets,
// for a SoC through the compile command of an ESP-IDF build). Names use "__" as the path separator
// of the ownership tree; "each__" marks the size of one pool/table entry. The array is one byte
// longer than the object so an empty object (size 0 is not a valid array bound) stays measurable.
// A slice that adds an owner table adds its line here.
#include "capi/context.hpp"
#include "port/idf/idf_radio.hpp"
#include "serial/root_usb.hpp"

#define LM_PROBE(name, bytes)                                                                     \
    extern "C" {                                                                                  \
    char lm_probe__##name[(bytes) + 1];                                                           \
    }

using namespace lm;

// ---- the context the application allocates (lm_workspace_required) ----
LM_PROBE(ctx, sizeof(lm_context))
LM_PROBE(ctx__engine, sizeof(Engine))
LM_PROBE(ctx__engine__job_table, sizeof(JobTable<k_job_table_entries>))
LM_PROBE(ctx__engine__app_events, sizeof(AppEventQueue<k_max_app_events>))
LM_PROBE(ctx__engine__peer_registry, sizeof(PeerRegistry))
LM_PROBE(ctx__engine__tx_manager, sizeof(TxManager))
LM_PROBE(ctx__engine__identity, sizeof(member::LocalIdentity))
LM_PROBE(ctx__engine__identity__record_job, sizeof(store::RecordJob))
LM_PROBE(ctx__engine__link, sizeof(link::LinkLayer))
LM_PROBE(ctx__engine__link__neighbors, sizeof(link::Neighbors))
LM_PROBE(each__neighbor, sizeof(link::Neighbor))
LM_PROBE(each__session_keys, sizeof(link::SessionKeys))
LM_PROBE(ctx__engine__link__exchange, sizeof(link::Exchange))
LM_PROBE(ctx__engine__link__exchange__handshake, sizeof(sec::HandshakeSlot))
LM_PROBE(ctx__engine__link__exchange__handshake__edhoc_session, sizeof(lm_edhoc_session))
LM_PROBE(ctx__engine__delivery, sizeof(delivery::Delivery))
LM_PROBE(ctx__engine__delivery__end_sessions, sizeof(delivery::EndSessions))
LM_PROBE(each__end_session, sizeof(delivery::EndSession))
LM_PROBE(ctx__engine__delivery__hop, sizeof(delivery::HopTx))
LM_PROBE(each__tx_frame, sizeof(delivery::TxFrame))
LM_PROBE(ctx__engine__frames, sizeof(TxPool))
LM_PROBE(ctx__engine__sched, sizeof(sched::Scheduler))
LM_PROBE(ctx__engine__delivery__durable, sizeof(delivery::Durable))
LM_PROBE(ctx__engine__delivery__durable__journal, sizeof(store::Journal))
LM_PROBE(ctx__engine__delivery__msg_pool, k_build_limits.app_messages * sizeof(delivery::MsgBuf))
LM_PROBE(ctx__engine__delivery__actives, delivery::k_actives * sizeof(delivery::Active))
LM_PROBE(ctx__engine__delivery__fragments, sizeof(delivery::FragState) + sizeof(std::array<uint8_t, wire::data_capacity(1)>))
LM_PROBE(each__active, sizeof(delivery::Active))
LM_PROBE(ctx__engine__delivery__in_entries, delivery::k_in_entries * sizeof(delivery::InEntry))
LM_PROBE(each__in_entry, sizeof(delivery::InEntry))
LM_PROBE(ctx__engine__delivery__in_live, delivery::k_in_live * sizeof(delivery::InLive))
LM_PROBE(each__in_live, sizeof(delivery::InLive))
LM_PROBE(ctx__engine__delivery__ops, delivery::k_ops * sizeof(delivery::Op))
LM_PROBE(each__op, sizeof(delivery::Op))
LM_PROBE(ctx__engine__roles, sizeof(OneOf<member::Membership, root::LedgerType>)) // P8: one of the two below
LM_PROBE(ctx__engine__membership, sizeof(member::Membership))
LM_PROBE(ctx__engine__membership__join_pipe, sizeof(member::JoinPipe))
LM_PROBE(ctx__engine__ledger, sizeof(root::LedgerType))
LM_PROBE(ctx__engine__mesh, sizeof(route::Mesh))
LM_PROBE(ctx__engine__routes, sizeof(root::RoutesType))
LM_PROBE(ctx__engine__chan, sizeof(channel::Channel))
LM_PROBE(ctx__engine__coordinator, sizeof(root::CoordinatorType))
LM_PROBE(ctx__engine__proxy, sizeof(member::Proxy))
LM_PROBE(ctx__engine__group, sizeof(group::Fanout))
LM_PROBE(ctx__engine__group__ops, group::k_ops * sizeof(group::Op))
LM_PROBE(each__group_op, sizeof(group::Op))
LM_PROBE(each__group_target, sizeof(group::Target))
LM_PROBE(ctx__engine__groups, sizeof(root::GroupsType))
LM_PROBE(ctx__engine__power, sizeof(power::Power))
LM_PROBE(each__power_member, sizeof(power::MemberPower))

// ---- static objects of the platform layer (src/port/idf, root: src/serial) ----
LM_PROBE(platform__radio, sizeof(idf::IdfRadio))
LM_PROBE(platform__radio__rx_ring, idf::IdfRadio::k_rx_ring * sizeof(port::RadioRx))
LM_PROBE(root__usb, sizeof(serial::RootUsb))
LM_PROBE(root__usb__link, sizeof(serial::UsbLink))
