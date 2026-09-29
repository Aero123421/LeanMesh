#include "core/delivery/durable.hpp"

#include "core/engine.hpp"

namespace lm::delivery {

Status Durable::job_entry(port::JobEnv &env, void *arg) {
    auto *d = static_cast<Durable *>(arg);
    switch (d->job_) {
    case Job::Boot: {
        LM_TRY(store::boot_job(env, &d->boot_));
        d->incarnation_ = d->boot_.incarnation;
        return d->journal_.open(env.store);
    }
    case Job::Put:
    case Job::Retire:
        return d->journal_.apply(env.store, &d->op_, 1);
    case Job::Read:
        return d->journal_.read(env.store, d->req_.id, MutByteView{d->boot_.rec.payload}, d->rec_len_);
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

Status Durable::begin_boot() {
    if (job_ != Job::None || cancelled_) {
        return Status::Busy;
    }
    state_ = State::Booting;
    queue_.clear();
    const Status st = submit(Job::Boot);
    if (st != Status::Ok) {
        state_ = State::Off;
    }
    return st;
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

Status Durable::read(uint32_t id) {
    if (state_ != State::Ready || job_ != Job::None) {
        return Status::Busy;
    }
    req_ = DurableReq{DurableReq::Op::Put, id, 0, 0};
    rec_len_ = 0;
    return submit(Job::Read);
}

void Durable::pump(MonoTime now) {
    while (state_ == State::Ready && job_ == Job::None && !queue_.empty()) {
        DurableReq r;
        (void)queue_.pop(r);
        req_ = r;
        if (r.op == DurableReq::Op::Retire) {
            op_ = store::JournalOp{store::JournalOp::Kind::Retire, r.id, ByteView{}};
        } else {
            std::size_t len = 0;
            Status st = hooks_.fill != nullptr
                            ? hooks_.fill(hooks_.ctx, r, MutByteView{boot_.rec.payload}, len)
                            : Status::RecoveryRequired;
            if (st != Status::Ok) {
                if (hooks_.done != nullptr) {
                    hooks_.done(hooks_.ctx, r, st, now);
                }
                continue;
            }
            op_ = store::JournalOp{store::JournalOp::Kind::Put, r.id,
                                   ByteView{boot_.rec.payload.data(), len}};
        }
        const Status st = submit(r.op == DurableReq::Op::Retire ? Job::Retire : Job::Put);
        if (st != Status::Ok) {
            if (hooks_.done != nullptr) {
                hooks_.done(hooks_.ctx, r, st, now); // worker queue full: the owner asks again
            }
        }
    }
}

void Durable::on_job_done(Handle slot, Status s, MonoTime now) {
    const Job j = job_;
    if (cancelled_) { // engine stopped meanwhile: the result is discarded, the memory is free again
        job_ = Job::None;
        cancelled_ = false;
        return;
    }
    if (slot != handle_ || j == Job::None) {
        return;
    }
    job_ = Job::None;
    switch (j) {
    case Job::Boot:
        state_ = s == Status::Ok ? State::Ready : State::Failed;
        if (hooks_.boot_done != nullptr) {
            hooks_.boot_done(hooks_.ctx, s, now);
        }
        break;
    case Job::Put:
    case Job::Retire:
        if (hooks_.done != nullptr) {
            hooks_.done(hooks_.ctx, req_, s, now);
        }
        break;
    case Job::Read:
        if (hooks_.read_done != nullptr) {
            hooks_.read_done(hooks_.ctx, req_.id, s, ByteView{boot_.rec.payload.data(), rec_len_}, now);
        }
        break;
    case Job::None:
        break;
    }
    pump(now);
}

void Durable::stop() {
    queue_.clear();
    state_ = State::Off;
    if (job_ != Job::None) {
        cancelled_ = true;
    }
}

} // namespace lm::delivery
