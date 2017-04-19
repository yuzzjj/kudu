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

#include "kudu/fs/file_block_manager.h"

#include <memory>
#include <string>
#include <vector>

#include "kudu/fs/block_manager_metrics.h"
#include "kudu/fs/data_dirs.h"
#include "kudu/gutil/strings/numbers.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/atomic.h"
#include "kudu/util/env.h"
#include "kudu/util/env_util.h"
#include "kudu/util/file_cache.h"
#include "kudu/util/malloc.h"
#include "kudu/util/mem_tracker.h"
#include "kudu/util/metrics.h"
#include "kudu/util/path_util.h"
#include "kudu/util/random_util.h"
#include "kudu/util/status.h"

using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::vector;
using strings::Substitute;

DECLARE_bool(enable_data_block_fsync);
DECLARE_bool(block_manager_lock_dirs);

namespace kudu {
namespace fs {

namespace internal {

////////////////////////////////////////////////////////////
// FileBlockLocation
////////////////////////////////////////////////////////////

// Logical location of a block in the file block manager.
//
// A block ID uniquely locates a block. Every ID is a uint64_t, broken down
// into multiple logical components:
// 1. Bytes 0 (MSB) and 1 identify the block's data dir by path set index. See
//    fs.proto for more details on path sets.
// 2. Bytes 2-7 (LSB) uniquely identify the block within the data dir. As more
//    and more blocks are created in a data dir, the likelihood of a collision
//    becomes greater. In the event of a collision, the block manager will
//    retry(see CreateBlock()).
//
// A FileBlockLocation abstracts away these details so that clients need not
// worry about them. It is constructed via FromParts() or FromBlockId() and is
// copyable and assignable.
class FileBlockLocation {
 public:
  // Empty constructor
  FileBlockLocation() {
  }

  // Construct a location from its constituent parts.
  static FileBlockLocation FromParts(DataDir* data_dir,
                                     uint16_t data_dir_idx,
                                     const BlockId& block_id);

  // Construct a location from a full block ID.
  static FileBlockLocation FromBlockId(DataDir* data_dir,
                                       const BlockId& block_id);

  // Get the data dir index of a given block ID.
  static uint16_t GetDataDirIdx(const BlockId& block_id) {
    return block_id.id() >> 48;
  }

  // Returns the full filesystem path for this location.
  string GetFullPath() const;

  // Create all subdirectories needed for this location.
  //
  // On success, 'created_dirs' contains the directories that were actually
  // created (as opposed to those that were reused).
  Status CreateBlockDir(Env* env, vector<string>* created_dirs);

  // Writes all parent directories that are part of this location to
  // 'parent_dirs'.
  //
  // The directories are written in "fsync order"; that is, the order in
  // which they should be fsynced to make them durable.
  void GetAllParentDirs(vector<string>* parent_dirs) const;

  // Simple accessors.
  DataDir* data_dir() const { return data_dir_; }
  const BlockId& block_id() const { return block_id_; }

 private:
  FileBlockLocation(DataDir* data_dir, BlockId block_id)
      : data_dir_(data_dir), block_id_(block_id) {}

  // These per-byte accessors yield subdirectories in which blocks are grouped.
  string byte2() const {
    return StringPrintf("%02llx",
                        (block_id_.id() & 0x0000FF0000000000ULL) >> 40);
  }
  string byte3() const {
    return StringPrintf("%02llx",
                        (block_id_.id() & 0x000000FF00000000ULL) >> 32);
  }
  string byte4() const {
    return StringPrintf("%02llx",
                        (block_id_.id() & 0x00000000FF000000ULL) >> 24);
  }

  DataDir* data_dir_;
  BlockId block_id_;
};

FileBlockLocation FileBlockLocation::FromParts(DataDir* data_dir,
                                               uint16_t data_dir_idx,
                                               const BlockId& block_id) {
  // The combined ID consists of 'data_dir_idx' (top 2 bytes) and 'block_id'
  // (bottom 6 bytes). The top 2 bytes of 'block_id' are dropped.
  uint64_t combined_id = static_cast<uint64_t>(data_dir_idx) << 48;
  combined_id |= block_id.id() & ((1ULL << 48) - 1);
  return FileBlockLocation(data_dir, BlockId(combined_id));
}

FileBlockLocation FileBlockLocation::FromBlockId(DataDir* data_dir,
                                                 const BlockId& block_id) {
  return FileBlockLocation(data_dir, block_id);
}

string FileBlockLocation::GetFullPath() const {
  string p = data_dir_->dir();
  p = JoinPathSegments(p, byte2());
  p = JoinPathSegments(p, byte3());
  p = JoinPathSegments(p, byte4());
  p = JoinPathSegments(p, block_id_.ToString());
  return p;
}

Status FileBlockLocation::CreateBlockDir(Env* env,
                                         vector<string>* created_dirs) {
  DCHECK(env->FileExists(data_dir_->dir()));

  bool path0_created;
  string path0 = JoinPathSegments(data_dir_->dir(), byte2());
  RETURN_NOT_OK(env_util::CreateDirIfMissing(env, path0, &path0_created));

  bool path1_created;
  string path1 = JoinPathSegments(path0, byte3());
  RETURN_NOT_OK(env_util::CreateDirIfMissing(env, path1, &path1_created));

  bool path2_created;
  string path2 = JoinPathSegments(path1, byte4());
  RETURN_NOT_OK(env_util::CreateDirIfMissing(env, path2, &path2_created));

  if (path2_created) {
    created_dirs->push_back(path1);
  }
  if (path1_created) {
    created_dirs->push_back(path0);
  }
  if (path0_created) {
    created_dirs->push_back(data_dir_->dir());
  }
  return Status::OK();
}

void FileBlockLocation::GetAllParentDirs(vector<string>* parent_dirs) const {
  string path0 = JoinPathSegments(data_dir_->dir(), byte2());
  string path1 = JoinPathSegments(path0, byte3());
  string path2 = JoinPathSegments(path1, byte4());

  // This is the order in which the parent directories should be
  // synchronized to disk.
  parent_dirs->push_back(path2);
  parent_dirs->push_back(path1);
  parent_dirs->push_back(path0);
  parent_dirs->push_back(data_dir_->dir());
}

////////////////////////////////////////////////////////////
// FileWritableBlock
////////////////////////////////////////////////////////////

// A file-backed block that has been opened for writing.
//
// Contains a pointer to the block manager as well as a FileBlockLocation
// so that dirty metadata can be synced via BlockManager::SyncMetadata()
// at Close() time. Embedding a FileBlockLocation (and not a simpler
// BlockId) consumes more memory, but the number of outstanding
// FileWritableBlock instances is expected to be low.
class FileWritableBlock : public WritableBlock {
 public:
  FileWritableBlock(FileBlockManager* block_manager, FileBlockLocation location,
                    shared_ptr<WritableFile> writer);

  virtual ~FileWritableBlock();

  virtual Status Close() OVERRIDE;

  virtual Status Abort() OVERRIDE;

  virtual BlockManager* block_manager() const OVERRIDE;

  virtual const BlockId& id() const OVERRIDE;

  virtual Status Append(const Slice& data) OVERRIDE;

  virtual Status FlushDataAsync() OVERRIDE;

  virtual size_t BytesAppended() const OVERRIDE;

  virtual State state() const OVERRIDE;

 private:
  enum SyncMode {
    SYNC,
    NO_SYNC
  };

  // Close the block, optionally synchronizing dirty data and metadata.
  Status Close(SyncMode mode);

  // Back pointer to the block manager.
  //
  // Should remain alive for the lifetime of this block.
  FileBlockManager* block_manager_;

  // The block's location.
  const FileBlockLocation location_;

  // The underlying opened file backing this block.
  shared_ptr<WritableFile> writer_;

  State state_;

  // The number of bytes successfully appended to the block.
  size_t bytes_appended_;

  DISALLOW_COPY_AND_ASSIGN(FileWritableBlock);
};

FileWritableBlock::FileWritableBlock(FileBlockManager* block_manager,
                                     FileBlockLocation location,
                                     shared_ptr<WritableFile> writer)
    : block_manager_(block_manager),
      location_(std::move(location)),
      writer_(std::move(writer)),
      state_(CLEAN),
      bytes_appended_(0) {
  if (block_manager_->metrics_) {
    block_manager_->metrics_->blocks_open_writing->Increment();
    block_manager_->metrics_->total_writable_blocks->Increment();
  }
}

FileWritableBlock::~FileWritableBlock() {
  if (state_ != CLOSED) {
    WARN_NOT_OK(Abort(), Substitute("Failed to close block $0",
                                    id().ToString()));
  }
}

Status FileWritableBlock::Close() {
  return Close(SYNC);
}

Status FileWritableBlock::Abort() {
  RETURN_NOT_OK(Close(NO_SYNC));
  return block_manager()->DeleteBlock(id());
}

BlockManager* FileWritableBlock::block_manager() const {
  return block_manager_;
}

const BlockId& FileWritableBlock::id() const {
  return location_.block_id();
}

Status FileWritableBlock::Append(const Slice& data) {
  DCHECK(state_ == CLEAN || state_ == DIRTY)
      << "Invalid state: " << state_;

  RETURN_NOT_OK(writer_->Append(data));
  RETURN_NOT_OK(location_.data_dir()->RefreshIsFull(
      DataDir::RefreshMode::ALWAYS));
  state_ = DIRTY;
  bytes_appended_ += data.size();
  return Status::OK();
}

Status FileWritableBlock::FlushDataAsync() {
  DCHECK(state_ == CLEAN || state_ == DIRTY || state_ == FLUSHING)
      << "Invalid state: " << state_;
  if (state_ == DIRTY) {
    VLOG(3) << "Flushing block " << id();
    RETURN_NOT_OK(writer_->Flush(WritableFile::FLUSH_ASYNC));
  }

  state_ = FLUSHING;
  return Status::OK();
}

size_t FileWritableBlock::BytesAppended() const {
  return bytes_appended_;
}

WritableBlock::State FileWritableBlock::state() const {
  return state_;
}

Status FileWritableBlock::Close(SyncMode mode) {
  if (state_ == CLOSED) {
    return Status::OK();
  }

  Status sync;
  if (mode == SYNC &&
      (state_ == CLEAN || state_ == DIRTY || state_ == FLUSHING)) {
    // Safer to synchronize data first, then metadata.
    VLOG(3) << "Syncing block " << id();
    if (FLAGS_enable_data_block_fsync) {
      sync = writer_->Sync();
    }
    if (sync.ok()) {
      sync = block_manager_->SyncMetadata(location_);
    }
    WARN_NOT_OK(sync, Substitute("Failed to sync when closing block $0",
                                 id().ToString()));
  }
  Status close = writer_->Close();

  state_ = CLOSED;
  writer_.reset();
  if (block_manager_->metrics_) {
    block_manager_->metrics_->blocks_open_writing->Decrement();
    block_manager_->metrics_->total_bytes_written->IncrementBy(BytesAppended());
  }

  // Prefer the result of Close() to that of Sync().
  return !close.ok() ? close : sync;
}

////////////////////////////////////////////////////////////
// FileReadableBlock
////////////////////////////////////////////////////////////

// A file-backed block that has been opened for reading.
//
// There may be millions of instances of FileReadableBlock outstanding, so
// great care must be taken to reduce its size. To that end, it does _not_
// embed a FileBlockLocation, using the simpler BlockId instead.
class FileReadableBlock : public ReadableBlock {
 public:
  FileReadableBlock(const FileBlockManager* block_manager, BlockId block_id,
                    shared_ptr<RandomAccessFile> reader);

  virtual ~FileReadableBlock();

  virtual Status Close() OVERRIDE;

  virtual const BlockId& id() const OVERRIDE;

  virtual Status Size(uint64_t* sz) const OVERRIDE;

  virtual Status Read(uint64_t offset, size_t length,
                      Slice* result, uint8_t* scratch) const OVERRIDE;

  virtual size_t memory_footprint() const OVERRIDE;

 private:
  // Back pointer to the owning block manager.
  const FileBlockManager* block_manager_;

  // The block's identifier.
  const BlockId block_id_;

  // The underlying opened file backing this block.
  shared_ptr<RandomAccessFile> reader_;

  // Whether or not this block has been closed. Close() is thread-safe, so
  // this must be an atomic primitive.
  AtomicBool closed_;

  DISALLOW_COPY_AND_ASSIGN(FileReadableBlock);
};

FileReadableBlock::FileReadableBlock(const FileBlockManager* block_manager,
                                     BlockId block_id,
                                     shared_ptr<RandomAccessFile> reader)
    : block_manager_(block_manager),
      block_id_(block_id),
      reader_(std::move(reader)),
      closed_(false) {
  if (block_manager_->metrics_) {
    block_manager_->metrics_->blocks_open_reading->Increment();
    block_manager_->metrics_->total_readable_blocks->Increment();
  }
}

FileReadableBlock::~FileReadableBlock() {
  WARN_NOT_OK(Close(), Substitute("Failed to close block $0",
                                  id().ToString()));
}

Status FileReadableBlock::Close() {
  if (closed_.CompareAndSet(false, true)) {
    reader_.reset();
    if (block_manager_->metrics_) {
      block_manager_->metrics_->blocks_open_reading->Decrement();
    }
  }

  return Status::OK();
}

const BlockId& FileReadableBlock::id() const {
  return block_id_;
}

Status FileReadableBlock::Size(uint64_t* sz) const {
  DCHECK(!closed_.Load());

  return reader_->Size(sz);
}

Status FileReadableBlock::Read(uint64_t offset, size_t length,
                               Slice* result, uint8_t* scratch) const {
  DCHECK(!closed_.Load());

  RETURN_NOT_OK(env_util::ReadFully(reader_.get(), offset, length, result, scratch));
  if (block_manager_->metrics_) {
    block_manager_->metrics_->total_bytes_read->IncrementBy(length);
  }

  return Status::OK();
}

size_t FileReadableBlock::memory_footprint() const {
  DCHECK(reader_);
  return kudu_malloc_usable_size(this) + reader_->memory_footprint();
}

} // namespace internal

////////////////////////////////////////////////////////////
// FileBlockManager
////////////////////////////////////////////////////////////

static const char* kBlockManagerType = "file";
static const int kMaxPaths = (1 << 16) - 1;

Status FileBlockManager::SyncMetadata(const internal::FileBlockLocation& location) {
  vector<string> parent_dirs;
  location.GetAllParentDirs(&parent_dirs);

  // Figure out what directories to sync.
  vector<string> to_sync;
  {
    std::lock_guard<simple_spinlock> l(lock_);
    for (const string& parent_dir : parent_dirs) {
      if (dirty_dirs_.erase(parent_dir)) {
        to_sync.push_back(parent_dir);
      }
    }
  }

  // Sync them.
  if (FLAGS_enable_data_block_fsync) {
    for (const string& s : to_sync) {
      RETURN_NOT_OK(env_->SyncDir(s));
    }
  }
  return Status::OK();
}

bool FileBlockManager::FindBlockPath(const BlockId& block_id,
                                     string* path) const {
  DataDir* dir = dd_manager_.FindDataDirByUuidIndex(
      internal::FileBlockLocation::GetDataDirIdx(block_id));
  if (dir) {
    *path = internal::FileBlockLocation::FromBlockId(
        dir, block_id).GetFullPath();
  }
  return dir != nullptr;
}

FileBlockManager::FileBlockManager(Env* env, const BlockManagerOptions& opts)
  : env_(DCHECK_NOTNULL(env)),
    read_only_(opts.read_only),
    dd_manager_(env, opts.metric_entity, kBlockManagerType, opts.root_paths),
    rand_(GetRandomSeed32()),
    next_block_id_(rand_.Next64()),
    mem_tracker_(MemTracker::CreateTracker(-1,
                                           "file_block_manager",
                                           opts.parent_mem_tracker)) {

  int64_t file_cache_capacity = GetFileCacheCapacityForBlockManager(env_);
  if (file_cache_capacity != kint64max) {
    file_cache_.reset(new FileCache<RandomAccessFile>("fbm",
                                                      env_,
                                                      file_cache_capacity,
                                                      opts.metric_entity));
  }

  if (opts.metric_entity) {
    metrics_.reset(new internal::BlockManagerMetrics(opts.metric_entity));
  }
}

FileBlockManager::~FileBlockManager() {
}

Status FileBlockManager::Create() {
  CHECK(!read_only_);
  return dd_manager_.Create(
      FLAGS_enable_data_block_fsync ? DataDirManager::FLAG_CREATE_FSYNC : 0);
}

Status FileBlockManager::Open() {
  DataDirManager::LockMode mode;
  if (!FLAGS_block_manager_lock_dirs) {
    mode = DataDirManager::LockMode::NONE;
  } else if (read_only_) {
    mode = DataDirManager::LockMode::OPTIONAL;
  } else {
    mode = DataDirManager::LockMode::MANDATORY;
  }
  RETURN_NOT_OK(dd_manager_.Open(kMaxPaths, mode));

  if (file_cache_) {
    RETURN_NOT_OK(file_cache_->Init());
  }
  return Status::OK();
}

Status FileBlockManager::CreateBlock(const CreateBlockOptions& opts,
                                     unique_ptr<WritableBlock>* block) {
  CHECK(!read_only_);

  DataDir* dir;
  RETURN_NOT_OK(dd_manager_.GetNextDataDir(&dir));
  uint16_t uuid_idx;
  CHECK(dd_manager_.FindUuidIndexByDataDir(dir, &uuid_idx));

  string path;
  vector<string> created_dirs;
  Status s;
  internal::FileBlockLocation location;
  shared_ptr<WritableFile> writer;

  int attempt_num = 0;
  // Repeat in case of block id collisions (unlikely).
  do {
    created_dirs.clear();

    // If we failed to generate a unique ID, start trying again from a random
    // part of the key space.
    if (attempt_num++ > 0) {
      next_block_id_.Store(rand_.Next64());
    }

    // Make sure we don't accidentally create a location using the magic
    // invalid ID value.
    BlockId id;
    do {
      id.SetId(next_block_id_.Increment());
    } while (id.IsNull());

    location = internal::FileBlockLocation::FromParts(dir, uuid_idx, id);
    path = location.GetFullPath();
    RETURN_NOT_OK_PREPEND(location.CreateBlockDir(env_, &created_dirs), path);
    WritableFileOptions wr_opts;
    wr_opts.mode = Env::CREATE_NON_EXISTING;
    s = env_util::OpenFileForWrite(wr_opts, env_, path, &writer);
  } while (PREDICT_FALSE(s.IsAlreadyPresent()));
  if (s.ok()) {
    VLOG(1) << "Creating new block " << location.block_id().ToString() << " at " << path;
    {
      // Update dirty_dirs_ with those provided as well as the block's
      // directory, which may not have been created but is definitely dirty
      // (because we added a file to it).
      std::lock_guard<simple_spinlock> l(lock_);
      for (const string& created : created_dirs) {
        dirty_dirs_.insert(created);
      }
      dirty_dirs_.insert(DirName(path));
    }
    block->reset(new internal::FileWritableBlock(this, location, writer));
  }
  return s;
}

Status FileBlockManager::CreateBlock(unique_ptr<WritableBlock>* block) {
  return CreateBlock(CreateBlockOptions(), block);
}

Status FileBlockManager::OpenBlock(const BlockId& block_id,
                                   unique_ptr<ReadableBlock>* block) {
  string path;
  if (!FindBlockPath(block_id, &path)) {
    return Status::NotFound(
        Substitute("Block $0 not found", block_id.ToString()));
  }

  VLOG(1) << "Opening block with id " << block_id.ToString() << " at " << path;

  shared_ptr<RandomAccessFile> reader;
  if (file_cache_) {
    RETURN_NOT_OK(file_cache_->OpenExistingFile(path, &reader));
  } else {
    RETURN_NOT_OK(env_util::OpenFileForRandom(env_, path, &reader));
  }
  block->reset(new internal::FileReadableBlock(this, block_id, reader));
  return Status::OK();
}

Status FileBlockManager::DeleteBlock(const BlockId& block_id) {
  CHECK(!read_only_);

  string path;
  if (!FindBlockPath(block_id, &path)) {
    return Status::NotFound(
        Substitute("Block $0 not found", block_id.ToString()));
  }
  if (file_cache_) {
    RETURN_NOT_OK(file_cache_->DeleteFile(path));
  } else {
    RETURN_NOT_OK(env_->DeleteFile(path));
  }

  // We don't bother fsyncing the parent directory as there's nothing to be
  // gained by ensuring that the deletion is made durable. Even if we did
  // fsync it, we'd need to account for garbage at startup time (in the
  // event that we crashed just before the fsync), and with such accounting
  // fsync-as-you-delete is unnecessary.
  //
  // The block's directory hierarchy is left behind. We could prune it if
  // it's empty, but that's racy and leaving it isn't much overhead.

  return Status::OK();
}

Status FileBlockManager::CloseBlocks(const vector<WritableBlock*>& blocks) {
  VLOG(3) << "Closing " << blocks.size() << " blocks";
  if (FLAGS_block_coalesce_close) {
    // Ask the kernel to begin writing out each block's dirty data. This is
    // done up-front to give the kernel opportunities to coalesce contiguous
    // dirty pages.
    for (WritableBlock* block : blocks) {
      RETURN_NOT_OK(block->FlushDataAsync());
    }
  }

  // Now close each block, waiting for each to become durable.
  for (WritableBlock* block : blocks) {
    RETURN_NOT_OK(block->Close());
  }
  return Status::OK();
}

namespace {

Status GetAllBlockIdsForDataDirCb(DataDir* dd,
                                  vector<BlockId>* block_ids,
                                  Env::FileType file_type,
                                  const string& dirname,
                                  const string& basename) {
  if (file_type != Env::FILE_TYPE) {
    // Skip directories.
    return Status::OK();
  }

  uint64_t numeric_id;
  if (!safe_strtou64(basename, &numeric_id)) {
    // Skip files with non-numerical names.
    return Status::OK();
  }

  // Verify that this block ID look-alike is, in fact, a block ID.
  //
  // We could also verify its contents, but that'd be quite expensive.
  BlockId block_id(numeric_id);
  internal::FileBlockLocation loc(
      internal::FileBlockLocation::FromBlockId(dd, block_id));
  if (loc.GetFullPath() != JoinPathSegments(dirname, basename)) {
    return Status::OK();
  }

  block_ids->push_back(block_id);
  return Status::OK();
}

void GetAllBlockIdsForDataDir(Env* env,
                              DataDir* dd,
                              vector<BlockId>* block_ids,
                              Status* status) {
  *status = env->Walk(dd->dir(), Env::PRE_ORDER,
                      Bind(&GetAllBlockIdsForDataDirCb, dd, block_ids));
}

} // anonymous namespace

Status FileBlockManager::GetAllBlockIds(vector<BlockId>* block_ids) {
  const auto& dds = dd_manager_.data_dirs();
  block_ids->clear();

  // The FBM does not maintain block listings in memory, so off we go to the
  // filesystem. The search is parallelized across data directories.
  vector<vector<BlockId>> block_id_vecs(dds.size());
  vector<Status> statuses(dds.size());
  for (int i = 0; i < dds.size(); i++) {
    dds[i]->ExecClosure(Bind(&GetAllBlockIdsForDataDir,
                             env_,
                             dds[i].get(),
                             &block_id_vecs[i],
                             &statuses[i]));
  }
  for (const auto& dd : dd_manager_.data_dirs()) {
    dd->WaitOnClosures();
  }

  // A failure on any data directory is fatal.
  for (const auto& s : statuses) {
    RETURN_NOT_OK(s);
  }

  // Collect the results into 'blocks'.
  for (const auto& ids : block_id_vecs) {
    block_ids->insert(block_ids->begin(), ids.begin(), ids.end());
  }
  return Status::OK();
}

} // namespace fs
} // namespace kudu
