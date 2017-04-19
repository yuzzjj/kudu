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
#ifndef KUDU_CONSENSUS_RAFT_CONSENSUS_UTIL_H_
#define KUDU_CONSENSUS_RAFT_CONSENSUS_UTIL_H_

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "kudu/consensus/consensus.h"
#include "kudu/consensus/consensus.pb.h"
#include "kudu/consensus/consensus_meta.h"
#include "kudu/consensus/log_util.h"
#include "kudu/consensus/opid_util.h"
#include "kudu/gutil/port.h"
#include "kudu/util/locks.h"
#include "kudu/util/status.h"

namespace kudu {

class HostPort;
class ThreadPool;

namespace rpc {
class Messenger;
}

namespace consensus {
class TimeManager;

// Class that coordinates access to the persistent Raft state (independently of Role).
// This has a 1-1 relationship with RaftConsensus and is essentially responsible for
// keeping state and checking if state changes are viable.
//
// Note that, in the case of a LEADER role, there are two configuration states that
// that are tracked: a pending and a committed configuration. The "active" state is
// considered to be the pending configuration if it is non-null, otherwise the
// committed configuration is the active configuration.
//
// TODO(todd): Currently this also performs some coarse-grained locking across the consensus
// implementation in addition to providing a fairly thin wrapper around ConsensusMetadata.
// The class should be renamed at the least and probably substantially simplified.
class ReplicaState {
 public:
  enum State {
    // State after the replica is built.
    kInitialized,

    // State signaling the replica accepts requests (from clients
    // if leader, from leader if follower)
    kRunning,

    // State signaling that the replica is shutting down and no longer accepting
    // new transactions or commits.
    kShuttingDown,

    // State signaling the replica is shut down and does not accept
    // any more requests.
    kShutDown
  };

  typedef std::unique_lock<simple_spinlock> UniqueLock;

  ReplicaState(ConsensusOptions options, std::string peer_uuid,
               std::unique_ptr<ConsensusMetadata> cmeta);

  Status StartUnlocked(const OpId& last_id_in_wal);

  // Locks a replica in preparation for StartUnlocked(). Makes
  // sure the replica is in kInitialized state.
  Status LockForStart(UniqueLock* lock) const WARN_UNUSED_RESULT;

  // Locks a replica down until the critical section of an append completes,
  // i.e. until the replicate message has been assigned an id and placed in
  // the log queue.
  // This also checks that the replica is in the appropriate
  // state (role) to replicate the provided operation, that the operation
  // contains a replicate message and is of the appropriate type, and returns
  // Status::IllegalState if that is not the case.
  Status LockForReplicate(UniqueLock* lock, const ReplicateMsg& msg) const WARN_UNUSED_RESULT;

  // Locks a replica down until the critical section of a commit completes.
  // This succeeds for all states since a replica which has initiated
  // a Prepare()/Replicate() must eventually commit even if it's state
  // has changed after the initial Append()/Update().
  Status LockForCommit(UniqueLock* lock) const WARN_UNUSED_RESULT;

  // Locks a replica down until an the critical section of an update completes.
  // Further updates from the same or some other leader will be blocked until
  // this completes. This also checks that the replica is in the appropriate
  // state (role) to be updated and returns Status::IllegalState if that
  // is not the case.
  Status LockForUpdate(UniqueLock* lock) const WARN_UNUSED_RESULT;

  // Changes the role to non-participant and returns a lock that can be
  // used to make sure no state updates come in until Shutdown() is
  // completed.
  Status LockForShutdown(UniqueLock* lock) WARN_UNUSED_RESULT;

  Status LockForConfigChange(UniqueLock* lock) const WARN_UNUSED_RESULT;

  // Obtains the lock for a state read, does not check state.
  Status LockForRead(UniqueLock* lock) const WARN_UNUSED_RESULT;

  // Ensure the local peer is the active leader.
  // Returns OK if leader, IllegalState otherwise.
  Status CheckActiveLeaderUnlocked() const;

  // Completes the Shutdown() of this replica. No more operations, local
  // or otherwise can happen after this point.
  // Called after the quiescing phase (started with LockForShutdown())
  // finishes.
  Status ShutdownUnlocked() WARN_UNUSED_RESULT;

  // Return current consensus state summary.
  ConsensusStatePB ConsensusStateUnlocked(ConsensusConfigType type) const {
    return cmeta_->ToConsensusStatePB(type);
  }

  // Returns the currently active Raft role.
  RaftPeerPB::Role GetActiveRoleUnlocked() const;

  // Returns true if there is a configuration change currently in-flight but not yet
  // committed.
  bool IsConfigChangePendingUnlocked() const;

  // Inverse of IsConfigChangePendingUnlocked(): returns OK if there is
  // currently *no* configuration change pending, and IllegalState is there *is* a
  // configuration change pending.
  Status CheckNoConfigChangePendingUnlocked() const;

  // Sets the given configuration as pending commit. Does not persist into the peers
  // metadata. In order to be persisted, SetCommittedConfigUnlocked() must be called.
  Status SetPendingConfigUnlocked(const RaftConfigPB& new_config) WARN_UNUSED_RESULT;

  // Clear (cancel) the pending configuration.
  void ClearPendingConfigUnlocked();

  // Return the pending configuration, or crash if one is not set.
  const RaftConfigPB& GetPendingConfigUnlocked() const;

  // Changes the committed config for this replica. Checks that there is a
  // pending configuration and that it is equal to this one. Persists changes to disk.
  // Resets the pending configuration to null.
  Status SetCommittedConfigUnlocked(const RaftConfigPB& committed_config);

  // Return the persisted configuration.
  const RaftConfigPB& GetCommittedConfigUnlocked() const;

  // Return the "active" configuration - if there is a pending configuration return it;
  // otherwise return the committed configuration.
  const RaftConfigPB& GetActiveConfigUnlocked() const;

  // Enum for the 'flush' argument to SetCurrentTermUnlocked() below.
  enum FlushToDisk {
    SKIP_FLUSH_TO_DISK,
    FLUSH_TO_DISK
  };

  // Checks if the term change is legal. If so, sets 'current_term'
  // to 'new_term' and sets 'has voted' to no for the current term.
  //
  // If the caller knows that it will call another method soon after
  // to flush the change to disk, it may set 'flush' to 'SKIP_FLUSH_TO_DISK'.
  Status SetCurrentTermUnlocked(int64_t new_term,
                                FlushToDisk flush) WARN_UNUSED_RESULT;

  // Returns the term set in the last config change round.
  const int64_t GetCurrentTermUnlocked() const;

  // Accessors for the leader of the current term.
  void SetLeaderUuidUnlocked(const std::string& uuid);
  const std::string& GetLeaderUuidUnlocked() const;
  bool HasLeaderUnlocked() const { return !GetLeaderUuidUnlocked().empty(); }
  void ClearLeaderUnlocked() { SetLeaderUuidUnlocked(""); }

  // Return whether this peer has voted in the current term.
  const bool HasVotedCurrentTermUnlocked() const;

  // Record replica's vote for the current term, then flush the consensus
  // metadata to disk.
  Status SetVotedForCurrentTermUnlocked(const std::string& uuid) WARN_UNUSED_RESULT;

  // Return replica's vote for the current term.
  // The vote must be set; use HasVotedCurrentTermUnlocked() to check.
  const std::string& GetVotedForCurrentTermUnlocked() const;

  // Returns the uuid of the peer to which this replica state belongs.
  // Safe to call with or without locks held.
  const std::string& GetPeerUuid() const;

  const ConsensusOptions& GetOptions() const;

  std::string ToString() const;
  std::string ToStringUnlocked() const;

  // A common prefix that should be in any log messages emitted,
  // identifying the tablet and peer.
  std::string LogPrefix();
  std::string LogPrefixUnlocked() const;

  // A variant of LogPrefix which does not take the lock. This is a slightly
  // less thorough prefix which only includes immutable (and thus thread-safe)
  // information, but does not require the lock.
  std::string LogPrefixThreadSafe() const;

  // Return the current state of this object.
  // The update_lock_ must be held.
  ReplicaState::State state() const;

  ConsensusMetadata* consensus_metadata_for_tests() {
    return cmeta_.get();
  }

 private:
  const ConsensusOptions options_;

  // The UUID of the local peer.
  const std::string peer_uuid_;

  mutable simple_spinlock update_lock_;

  // Consensus metadata persistence object.
  std::unique_ptr<ConsensusMetadata> cmeta_;

  State state_;
};

// Tracks the pending consensus rounds being managed by a Raft replica (either leader
// or follower).
//
// This class is not thread-safe.
//
// TODO(todd): this class inconsistently uses the term "round", "op", and "transaction".
// We should consolidate to "round".
class PendingRounds {
 public:
  PendingRounds(std::string log_prefix, scoped_refptr<TimeManager> time_manager);
  ~PendingRounds();

  // Set the committed op during startup. This should be done after
  // appending any of the pending transactions, and will take care
  // of triggering any that are now considered committed.
  Status SetInitialCommittedOpId(const OpId& committed_op);

  // Returns the the ConsensusRound with the provided index, if there is any, or NULL
  // if there isn't.
  scoped_refptr<ConsensusRound> GetPendingOpByIndexOrNull(int64_t index);

  // Add 'round' to the set of rounds waiting to be committed.
  Status AddPendingOperation(const scoped_refptr<ConsensusRound>& round);

  // Advances the committed index.
  // This is a no-op if the committed index has not changed.
  Status AdvanceCommittedIndex(int64_t committed_index);

  // Aborts pending operations after, but not including 'index'. The OpId with 'index'
  // will become our new last received id. If there are pending operations with indexes
  // higher than 'index' those operations are aborted.
  void AbortOpsAfter(int64_t index);

  // Returns true if an operation is in this replica's log, namely:
  // - If the op's index is lower than or equal to our committed index
  // - If the op id matches an inflight op.
  // If an operation with the same index is in our log but the terms
  // are different 'term_mismatch' is set to true, it is false otherwise.
  bool IsOpCommittedOrPending(const OpId& op_id, bool* term_mismatch);

  // Returns the id of the latest pending transaction (i.e. the one with the
  // latest index). This must be called under the lock.
  OpId GetLastPendingTransactionOpId() const;

  // Used by replicas to cancel pending transactions. Pending transaction are those
  // that have completed prepare/replicate but are waiting on the LEADER's commit
  // to complete. This does not cancel transactions being applied.
  Status CancelPendingTransactions();

  // Returns the number of transactions that are currently in the pending state
  // i.e. transactions for which Prepare() is done or under way.
  int GetNumPendingTxns() const;

  // Returns the watermark below which all operations are known to
  // be committed according to consensus.
  // TODO(todd): these should probably be removed in favor of using the queue.
  int64_t GetCommittedIndex() const;
  int64_t GetTermWithLastCommittedOp() const;

  // Checks that 'current' correctly follows 'previous'. Specifically it checks
  // that the term is the same or higher and that the index is sequential.
  static Status CheckOpInSequence(const OpId& previous, const OpId& current);

 private:
  const std::string& LogPrefix() const { return log_prefix_; }

  const std::string log_prefix_;

  // Index=>Round map that manages pending ops, i.e. operations for which we've
  // received a replicate message from the leader but have yet to be committed.
  // The key is the index of the replicate operation.
  typedef std::map<int64_t, scoped_refptr<ConsensusRound> > IndexToRoundMap;
  IndexToRoundMap pending_txns_;

  // The OpId of the round that was last committed. Initialized to MinimumOpId().
  OpId last_committed_op_id_;

  scoped_refptr<TimeManager> time_manager_;
};

}  // namespace consensus
}  // namespace kudu

#endif /* KUDU_CONSENSUS_RAFT_CONSENSUS_UTIL_H_ */
