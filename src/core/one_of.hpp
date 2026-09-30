// One of two owner objects in one storage, chosen once at construction (ADR-002 P8). For owners of which a node
// uses exactly one by a fact fixed at initialisation (its role): the joiner/member side or the root's ledger. No
// heap, no RTTI: the choice is a flag, and reaching for the other object is an internal invariant failure.
#pragma once

#include <algorithm>
#include <cstddef>
#include <new>

#include "core/assert.hpp"

namespace lm {

template <class A, class B> class OneOf {
  public:
    // Builds A when `use_a`, else B, from the same constructor argument.
    template <class Arg> OneOf(bool use_a, Arg &arg) : use_a_(use_a) {
        if (use_a_) {
            new (storage_) A(arg);
        } else {
            new (storage_) B(arg);
        }
    }
    ~OneOf() {
        if (use_a_) {
            a().~A();
        } else {
            b().~B();
        }
    }
    OneOf(const OneOf &) = delete;
    OneOf &operator=(const OneOf &) = delete;

    [[nodiscard]] bool holds_a() const { return use_a_; }
    [[nodiscard]] A &a() {
        LM_ASSERT(use_a_);
        return *std::launder(reinterpret_cast<A *>(storage_));
    }
    [[nodiscard]] const A &a() const {
        LM_ASSERT(use_a_);
        return *std::launder(reinterpret_cast<const A *>(storage_));
    }
    [[nodiscard]] B &b() {
        LM_ASSERT(!use_a_);
        return *std::launder(reinterpret_cast<B *>(storage_));
    }
    [[nodiscard]] const B &b() const {
        LM_ASSERT(!use_a_);
        return *std::launder(reinterpret_cast<const B *>(storage_));
    }

  private:
    alignas(A) alignas(B) unsigned char storage_[std::max(sizeof(A), sizeof(B))];
    bool use_a_;
};

} // namespace lm
