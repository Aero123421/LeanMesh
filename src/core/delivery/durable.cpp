#include "core/delivery/durable.hpp"

#include "core/engine.hpp"

namespace lm::delivery {
namespace {

constexpr Duration k_submit_retry = Duration::from_ms(20); // job table / worker queue full: local, not storage trouble

} // namespace

// Worker. Only the borrowed record memory and the journal are touched (the owner leaves both alone meanwhile).
Status Durable::job_entry(port::JobEnv &env, void *arg) {
    auto *d = static_cast<Durable *>(arg);
    store::RecordJob &rec = *d->rec_;
    const MutByteView staging{rec.scratch};
    switch (d->job_) {
    case Job::Boot:
        LM_TRY(store::boot_incarnation_advance(env.store, rec, d->boot_out_));
        return d->journal_.open(env.store, staging);
    case Job::Put:
    case Job::Retire:
        return d->journal_.apply(env.store, staging, &d->op_, 1);
    case Job::Read:
        return d->journal_.read(env.store, staging, d->req_.id, MutByteView{rec.payload}, d->rec_len_);
    case Job::None:
        break;
    }
    return Status::RecoveryRequired;
}

Status Durable::submit(Job j) {
    job_ = j;
    handle_ = Handle{0, ++handle_gen_};
    const Status st = engine_.submit_job(JobOwner::Durable, handle_, JobClass::Flash, &job_entry, this);
    if (st != Status::Ok) {
        job_ = Job::None;
    }
    return st;
}

void Durable::give_back() {
    if (rec_ != nullptr) {
        engine_.identity().return_record(rec_);
    }
}

bool Durable::wants_job() const {
    return job_ == Job::None && !cancelled_ && rec_ == nullptr &&
           ((state_ == State::Booting && boot_wanted_) || (state_ == State::Ready && (read_wanted_ || !queue_.empty())));
}

Status Durable::begin_boot(MonoTime now) {
    if (job_ != Job::None || cancelled_) {
        return Status::Busy;
    }
    state_ = State::Booting;
    queue_.clear();
    boot_wanted_ = true;
    read_wanted_ = false;
    retry_at_ = MonoTime::never();
    pump(now); // the identity's own load usually holds the memory now: the boot runs once it is back
    return Status::Ok;
}

bool Durable::enqueue(const DurableReq &req, MonoTime now) {
    if (state_ != State::Ready) {
        return false;
    }
    // A queued write of the same record is replaced: its record is built from the newest state.
    bool merged = false;
    const std::size_t n = queue_.size();
    for (std::size_t i = 0; i < n; ++i) {
        DurableReq r;
        (void)queue_.pop(r);
        if (r.id == req.id && r.op == req.op) {
            r.gen = req.gen;
            r.version = req.version;
            merged = true;
        }
        (void)queue_.push(r);
    }
    if (!merged && !queue_.push(req)) {
        return false;
    }
    pump(now);
    return true;
}

Status Durable::read(uint32_t id, MonoTime now) {
    if (state_ != State::Ready || read_wanted_) {
        return Status::Busy;
    }
    read_id_ = id;
    read_wanted_ = true;
    pump(now);
    return Status::Ok;
}

void Durable::pump(MonoTime now) {
    while (wants_job() && (retry_at_.is_never() || now >= retry_at_)) {
        retry_at_ = MonoTime::never();
        rec_ = engine_.identity().lend_record();
        if (rec_ == nullptr) {
            return; // another module's job holds it: deadline() is "now" once it is given back
        }
        if (state_ == State::Booting || read_wanted_) {
            if (read_wanted_ && state_ == State::Ready) {
                req_ = DurableReq{DurableReq::Op::Put, read_id_, 0, 0};
                rec_len_ = 0;
            }
            if (submit(state_ == State::Booting ? Job::Boot : Job::Read) != Status::Ok) {
                give_back();
                retry_at_ = now + k_submit_retry;
            }
            return;
        }
        const DurableReq r = *queue_.front();
        req_ = r;
        std::size_t len = 0;
        Status st = Status::Ok;
        if (r.op == DurableReq::Op::Put) {
            st = hooks_.fill != nullptr ? hooks_.fill(hooks_.ctx, r, MutByteView{rec_->payload}, len)
                                        : Status::RecoveryRequired;
        }
        if (st != Status::Ok) { // the fill's refusal (the record finished meanwhile): reported, not retried
            (void)queue_.pop(req_);
            give_back();
            if (hooks_.done != nullptr) {
                hooks_.done(hooks_.ctx, r, st, now);
            }
            continue;
        }
        op_ = r.op == DurableReq::Op::Retire
                  ? store::JournalOp{store::JournalOp::Kind::Retire, r.id, ByteView{}}
                  : store::JournalOp{store::JournalOp::Kind::Put, r.id, ByteView{rec_->payload.data(), len}};
        if (submit(r.op == DurableReq::Op::Retire ? Job::Retire : Job::Put) != Status::Ok) {
            // The job table or the worker queue is full (local): the write stays queued and is tried again shortly.
            // (Reporting BUSY made its owner enqueue it again at once, a recursion while the table stayed full.)
            give_back();
            retry_at_ = now + k_submit_retry;
            return;
        }
        (void)queue_.pop(req_);
        return;
    }
}

MonoTime Durable::deadline() const {
    if (!wants_job()) {
        return MonoTime::never();
    }
    if (!retry_at_.is_never()) {
        return retry_at_;
    }
    return engine_.identity().record_free() ? MonoTime{0} : MonoTime::never(); // known work, the memory is back
}

void Durable::on_job_done(Handle slot, Status s, MonoTime now) {
    if (cancelled_) { // engine stopped meanwhile: the result is discarded, the memory goes back
        job_ = Job::None;
        cancelled_ = false;
        give_back();
        return;
    }
    const Job j = job_;
    if (slot != handle_ || j == Job::None) {
        return;
    }
    job_ = Job::None;
    switch (j) {
    case Job::Boot:
        give_back();
        boot_wanted_ = false;
        incarnation_ = s == Status::Ok ? boot_out_ : incarnation_;
        state_ = s == Status::Ok ? State::Ready : State::Failed;
        if (hooks_.boot_done != nullptr) {
            hooks_.boot_done(hooks_.ctx, s, now);
        }
        break;
    case Job::Put:
    case Job::Retire:
        give_back();
        if (hooks_.done != nullptr) {
            hooks_.done(hooks_.ctx, req_, s, now);
        }
        break;
    case Job::Read:
        read_wanted_ = false;
        if (hooks_.read_done != nullptr) { // the record lives in the borrowed memory: returned after the call
            hooks_.read_done(hooks_.ctx, req_.id, s, ByteView{rec_->payload.data(), rec_len_}, now);
        }
        give_back();
        break;
    case Job::None:
        break;
    }
    pump(now);
}

void Durable::stop() {
    queue_.clear();
    state_ = State::Off;
    boot_wanted_ = read_wanted_ = false;
    retry_at_ = MonoTime::never();
    if (job_ != Job::None) {
        cancelled_ = true; // the borrowed memory stays with the job until its completion is polled
    }
}

} // namespace lm::delivery
