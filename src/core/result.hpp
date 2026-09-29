// Result<T>: a value or a non-OK Status. No exceptions (docs/15 §2).
#pragma once

#include <optional>
#include <utility>

#include "core/assert.hpp"
#include "core/status.hpp"

namespace lm {

template <class T> class [[nodiscard]] Result {
  public:
    // NOLINTNEXTLINE(google-explicit-constructor): implicit to allow `return value;`.
    Result(T value) : value_(std::move(value)), status_(Status::Ok) {}
    // NOLINTNEXTLINE(google-explicit-constructor): implicit to allow `return Status::X;`.
    Result(Status status) : status_(status) { LM_ASSERT(status != Status::Ok); }

    [[nodiscard]] bool ok() const { return status_ == Status::Ok; }
    [[nodiscard]] Status status() const { return status_; }

    [[nodiscard]] T &value() & {
        LM_ASSERT(ok());
        return *value_;
    }
    [[nodiscard]] const T &value() const & {
        LM_ASSERT(ok());
        return *value_;
    }
    [[nodiscard]] T &&value() && {
        LM_ASSERT(ok());
        return std::move(*value_);
    }

  private:
    std::optional<T> value_;
    Status status_;
};

} // namespace lm
