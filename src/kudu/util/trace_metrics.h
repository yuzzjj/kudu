// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
#pragma once

#include "kudu/gutil/macros.h"
#include "kudu/gutil/map-util.h"
#include "kudu/util/atomic.h"
#include "kudu/util/locks.h"

#include <map>
#include <mutex>
#include <string>

namespace kudu {

// A simple map of constant string names to integer counters.
//
// Typically, the TRACE_COUNTER_INCREMENT(...) macro defined in
// trace.h is used to increment a counter within this map.
//
// This currently is just a thin wrapper around a spinlocked map,
// but if it becomes noticeable in the CPU profile, various optimizations
// are plausible.
class TraceMetrics {
 public:
  TraceMetrics() : tcmalloc_contention_cycles_(0) {}
  ~TraceMetrics() {}

  // Internalize the given string by duplicating it into a process-wide
  // pool. If this string has already been interned, returns a pointer
  // to a previous instance. Otherwise, copies it into the pool.
  //
  // The resulting strings are purposefully leaked, so this should only
  // be used in cases where the number of unique strings that will be
  // passed is relatively low (i.e. not user-specified).
  //
  // Because 'name' is exposed back to operators, it must be a printable
  // ASCII string.
  static const char* InternName(const std::string& name);

  // Increment the given counter.
  void Increment(const char* name, int64_t amount);

  // Return a copy of the current counter map.
  std::map<const char*, int64_t> Get() const;

  // Increment the number of cycles spent in tcmalloc lock contention.
  //
  // tcmalloc contention is stored separately from other metrics since
  // it is incremented from a code path that prohibits allocation.
  void IncrementTcmallocContentionCycles(int64_t cycles) {
    tcmalloc_contention_cycles_.IncrementBy(cycles);
  }

  // Return metric's current value.
  //
  // NOTE: the 'name' MUST be the same const char* which is used for
  // insertion. This is because we do pointer-wise comparison internally.
  int64_t GetMetric(const char* name) const;

 private:
  mutable simple_spinlock lock_;
  std::map<const char*, int64_t> counters_;
  AtomicInt<int64_t> tcmalloc_contention_cycles_;

  DISALLOW_COPY_AND_ASSIGN(TraceMetrics);
};

inline void TraceMetrics::Increment(const char* name, int64_t amount) {
  std::lock_guard<simple_spinlock> l(lock_);
  counters_[name] += amount;
}

inline std::map<const char*, int64_t> TraceMetrics::Get() const {
  std::unique_lock<simple_spinlock> l(lock_);
  auto m = counters_;
  l.unlock();

  auto v = tcmalloc_contention_cycles_.Load();
  if (v > 0) {
    m["tcmalloc_contention_cycles"] = v;
  }
  return m;
}

inline int64_t TraceMetrics::GetMetric(const char* name) const {
  std::lock_guard<simple_spinlock> l(lock_);
  return FindWithDefault(counters_, name, 0);
}

} // namespace kudu
