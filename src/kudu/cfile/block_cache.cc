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

#include <gflags/gflags.h>

#include "kudu/cfile/block_cache.h"
#include "kudu/gutil/port.h"
#include "kudu/util/cache.h"
#include "kudu/util/flag_tags.h"
#include "kudu/util/metrics.h"
#include "kudu/util/slice.h"
#include "kudu/util/string_case.h"

DEFINE_int64(block_cache_capacity_mb, 512, "block cache capacity in MB");
TAG_FLAG(block_cache_capacity_mb, stable);

DEFINE_string(block_cache_type, "DRAM",
              "Which type of block cache to use for caching data. "
              "Valid choices are 'DRAM' or 'NVM'. DRAM, the default, "
              "caches data in regular memory. 'NVM' caches data "
              "in a memory-mapped file using the NVML library.");
TAG_FLAG(block_cache_type, experimental);

namespace kudu {

class MetricEntity;

namespace cfile {

namespace {

Cache* CreateCache(int64_t capacity) {
  CacheType t;
  ToUpperCase(FLAGS_block_cache_type, &FLAGS_block_cache_type);
  if (FLAGS_block_cache_type == "NVM") {
    t = NVM_CACHE;
  } else if (FLAGS_block_cache_type == "DRAM") {
    t = DRAM_CACHE;
  } else {
    LOG(FATAL) << "Unknown block cache type: '" << FLAGS_block_cache_type
               << "' (expected 'DRAM' or 'NVM')";
  }
  return NewLRUCache(t, capacity, "block_cache");
}

} // anonymous namespace

BlockCache::BlockCache()
  : BlockCache(FLAGS_block_cache_capacity_mb * 1024 * 1024) {
}

BlockCache::BlockCache(size_t capacity)
  : cache_(CreateCache(capacity)) {
}

BlockCache::PendingEntry BlockCache::Allocate(const CacheKey& key, size_t val_size) {
  Slice key_slice(reinterpret_cast<const uint8_t*>(&key), sizeof(key));
  int charge = val_size;
  return PendingEntry(cache_.get(), cache_->Allocate(key_slice, val_size, charge));
}

bool BlockCache::Lookup(const CacheKey& key, Cache::CacheBehavior behavior,
                        BlockCacheHandle *handle) {
  Cache::Handle *h = cache_->Lookup(Slice(reinterpret_cast<const uint8_t*>(&key),
                                          sizeof(key)), behavior);
  if (h != nullptr) {
    handle->SetHandle(cache_.get(), h);
  }
  return h != nullptr;
}

void BlockCache::Insert(BlockCache::PendingEntry* entry, BlockCacheHandle* inserted) {
  Cache::Handle *h = cache_->Insert(entry->handle_, /* eviction_callback= */ nullptr);
  entry->handle_ = nullptr;
  inserted->SetHandle(cache_.get(), h);
}

void BlockCache::StartInstrumentation(const scoped_refptr<MetricEntity>& metric_entity) {
  cache_->SetMetrics(metric_entity);
}

} // namespace cfile
} // namespace kudu
