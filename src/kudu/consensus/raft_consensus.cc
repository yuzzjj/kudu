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

#include "kudu/consensus/raft_consensus.h"

#include <algorithm>
#include <boost/optional.hpp>
#include <gflags/gflags.h>
#include <iostream>
#include <memory>
#include <mutex>

#include "kudu/common/wire_protocol.h"
#include "kudu/consensus/consensus.pb.h"
#include "kudu/consensus/consensus_peers.h"
#include "kudu/consensus/leader_election.h"
#include "kudu/consensus/log.h"
#include "kudu/consensus/metadata.pb.h"
#include "kudu/consensus/peer_manager.h"
#include "kudu/consensus/quorum_util.h"
#include "kudu/consensus/raft_consensus_state.h"
#include "kudu/gutil/map-util.h"
#include "kudu/gutil/stl_util.h"
#include "kudu/gutil/stringprintf.h"
#include "kudu/server/clock.h"
#include "kudu/util/debug/trace_event.h"
#include "kudu/util/flag_tags.h"
#include "kudu/util/logging.h"
#include "kudu/util/mem_tracker.h"
#include "kudu/util/metrics.h"
#include "kudu/util/pb_util.h"
#include "kudu/util/random.h"
#include "kudu/util/random_util.h"
#include "kudu/util/threadpool.h"
#include "kudu/util/trace.h"
#include "kudu/util/url-coding.h"

DEFINE_int32(raft_heartbeat_interval_ms, 500,
             "The heartbeat interval for Raft replication. The leader produces heartbeats "
             "to followers at this interval. The followers expect a heartbeat at this interval "
             "and consider a leader to have failed if it misses several in a row.");
TAG_FLAG(raft_heartbeat_interval_ms, advanced);

// Defaults to be the same value as the leader heartbeat interval.
DEFINE_int32(leader_failure_monitor_check_mean_ms, -1,
             "The mean failure-checking interval of the randomized failure monitor. If this "
             "is configured to -1 (the default), uses the value of 'raft_heartbeat_interval_ms'.");
TAG_FLAG(leader_failure_monitor_check_mean_ms, experimental);

// Defaults to half of the mean (above).
DEFINE_int32(leader_failure_monitor_check_stddev_ms, -1,
             "The standard deviation of the failure-checking interval of the randomized "
             "failure monitor. If this is configured to -1 (the default), this is set to "
             "half of the mean check interval.");
TAG_FLAG(leader_failure_monitor_check_stddev_ms, experimental);

DEFINE_double(leader_failure_max_missed_heartbeat_periods, 3.0,
             "Maximum heartbeat periods that the leader can fail to heartbeat in before we "
             "consider the leader to be failed. The total failure timeout in milliseconds is "
             "raft_heartbeat_interval_ms times leader_failure_max_missed_heartbeat_periods. "
             "The value passed to this flag may be fractional.");
TAG_FLAG(leader_failure_max_missed_heartbeat_periods, advanced);

DEFINE_int32(leader_failure_exp_backoff_max_delta_ms, 20 * 1000,
             "Maximum time to sleep in between leader election retries, in addition to the "
             "regular timeout. When leader election fails the interval in between retries "
             "increases exponentially, up to this value.");
TAG_FLAG(leader_failure_exp_backoff_max_delta_ms, experimental);

DEFINE_bool(enable_leader_failure_detection, true,
            "Whether to enable failure detection of tablet leaders. If enabled, attempts will be "
            "made to elect a follower as a new leader when the leader is detected to have failed.");
TAG_FLAG(enable_leader_failure_detection, unsafe);

DEFINE_bool(evict_failed_followers, true,
            "Whether to evict followers from the Raft config that have fallen "
            "too far behind the leader's log to catch up normally or have been "
            "unreachable by the leader for longer than "
            "follower_unavailable_considered_failed_sec");
TAG_FLAG(evict_failed_followers, advanced);

DEFINE_bool(follower_reject_update_consensus_requests, false,
            "Whether a follower will return an error for all UpdateConsensus() requests. "
            "Warning! This is only intended for testing.");
TAG_FLAG(follower_reject_update_consensus_requests, unsafe);

DEFINE_bool(follower_fail_all_prepare, false,
            "Whether a follower will fail preparing all transactions. "
            "Warning! This is only intended for testing.");
TAG_FLAG(follower_fail_all_prepare, unsafe);

DEFINE_bool(raft_enable_pre_election, true,
            "When enabled, candidates will call a pre-election before "
            "running a real leader election.");
TAG_FLAG(raft_enable_pre_election, experimental);
TAG_FLAG(raft_enable_pre_election, runtime);

DECLARE_int32(memory_limit_warn_threshold_percentage);

// Metrics
// ---------
METRIC_DEFINE_counter(tablet, follower_memory_pressure_rejections,
                      "Follower Memory Pressure Rejections",
                      kudu::MetricUnit::kRequests,
                      "Number of RPC requests rejected due to "
                      "memory pressure while FOLLOWER.");
METRIC_DEFINE_gauge_int64(tablet, raft_term,
                          "Current Raft Consensus Term",
                          kudu::MetricUnit::kUnits,
                          "Current Term of the Raft Consensus algorithm. This number increments "
                          "each time a leader election is started.");

namespace  {

// Return the mean interval at which to check for failures of the
// leader.
int GetFailureMonitorCheckMeanMs() {
  int val = FLAGS_leader_failure_monitor_check_mean_ms;
  if (val < 0) {
    val = FLAGS_raft_heartbeat_interval_ms;
  }
  return val;
}

// Return the standard deviation for the interval at which to check
// for failures of the leader.
int GetFailureMonitorCheckStddevMs() {
  int val = FLAGS_leader_failure_monitor_check_stddev_ms;
  if (val < 0) {
    val = GetFailureMonitorCheckMeanMs() / 2;
  }
  return val;
}

} // anonymous namespace

namespace kudu {
namespace consensus {

using std::shared_ptr;
using std::unique_ptr;
using strings::Substitute;
using tserver::TabletServerErrorPB;

// Special string that represents any known leader to the failure detector.
static const char* const kTimerId = "election-timer";

scoped_refptr<RaftConsensus> RaftConsensus::Create(
    const ConsensusOptions& options,
    unique_ptr<ConsensusMetadata> cmeta,
    const RaftPeerPB& local_peer_pb,
    const scoped_refptr<MetricEntity>& metric_entity,
    scoped_refptr<TimeManager> time_manager,
    ReplicaTransactionFactory* txn_factory,
    const shared_ptr<rpc::Messenger>& messenger,
    const scoped_refptr<log::Log>& log,
    const shared_ptr<MemTracker>& parent_mem_tracker,
    const Callback<void(const std::string& reason)>& mark_dirty_clbk) {
  gscoped_ptr<PeerProxyFactory> rpc_factory(new RpcPeerProxyFactory(messenger));

  // The message queue that keeps track of which operations need to be replicated
  // where.
  gscoped_ptr<PeerMessageQueue> queue(new PeerMessageQueue(metric_entity,
                                                           log,
                                                           time_manager,
                                                           local_peer_pb,
                                                           options.tablet_id));

  gscoped_ptr<ThreadPool> thread_pool;
  CHECK_OK(ThreadPoolBuilder(Substitute("$0-raft", options.tablet_id.substr(0, 6)))
           .set_trace_metric_prefix("raft")
           .set_idle_timeout(MonoDelta::FromMilliseconds(FLAGS_raft_heartbeat_interval_ms * 2))
           .Build(&thread_pool));

  DCHECK(local_peer_pb.has_permanent_uuid());
  const string& peer_uuid = local_peer_pb.permanent_uuid();

  // A manager for the set of peers that actually send the operations both remotely
  // and to the local wal.
  gscoped_ptr<PeerManager> peer_manager(
    new PeerManager(options.tablet_id,
                    peer_uuid,
                    rpc_factory.get(),
                    queue.get(),
                    thread_pool.get(),
                    log));

  return make_scoped_refptr(new RaftConsensus(
                              options,
                              std::move(cmeta),
                              std::move(rpc_factory),
                              std::move(queue),
                              std::move(peer_manager),
                              std::move(thread_pool),
                              metric_entity,
                              peer_uuid,
                              std::move(time_manager),
                              txn_factory,
                              log,
                              parent_mem_tracker,
                              mark_dirty_clbk));
}

RaftConsensus::RaftConsensus(
    const ConsensusOptions& options,
    unique_ptr<ConsensusMetadata> cmeta,
    gscoped_ptr<PeerProxyFactory> peer_proxy_factory,
    gscoped_ptr<PeerMessageQueue> queue,
    gscoped_ptr<PeerManager> peer_manager,
    gscoped_ptr<ThreadPool> thread_pool,
    const scoped_refptr<MetricEntity>& metric_entity,
    const std::string& peer_uuid,
    scoped_refptr<TimeManager> time_manager,
    ReplicaTransactionFactory* txn_factory,
    const scoped_refptr<log::Log>& log,
    shared_ptr<MemTracker> parent_mem_tracker,
    Callback<void(const std::string& reason)> mark_dirty_clbk)
    : thread_pool_(std::move(thread_pool)),
      log_(log),
      time_manager_(std::move(time_manager)),
      peer_proxy_factory_(std::move(peer_proxy_factory)),
      txn_factory_(txn_factory),
      peer_manager_(std::move(peer_manager)),
      queue_(std::move(queue)),
      pending_(Substitute("T $0 P $1: ", options.tablet_id, peer_uuid), time_manager_),
      rng_(GetRandomSeed32()),
      failure_monitor_(GetRandomSeed32(), GetFailureMonitorCheckMeanMs(),
                       GetFailureMonitorCheckStddevMs()),
      failure_detector_(new TimedFailureDetector(MonoDelta::FromMilliseconds(
          FLAGS_raft_heartbeat_interval_ms *
          FLAGS_leader_failure_max_missed_heartbeat_periods))),
      withhold_votes_until_(MonoTime::Min()),
      last_received_cur_leader_(MinimumOpId()),
      failed_elections_since_stable_leader_(0),
      mark_dirty_clbk_(std::move(mark_dirty_clbk)),
      shutdown_(false),
      update_calls_for_tests_(0),
      follower_memory_pressure_rejections_(metric_entity->FindOrCreateCounter(
          &METRIC_follower_memory_pressure_rejections)),
      term_metric_(metric_entity->FindOrCreateGauge(&METRIC_raft_term,
                                                    cmeta->current_term())),
      parent_mem_tracker_(std::move(parent_mem_tracker)) {
  DCHECK(log_);
  state_.reset(new ReplicaState(options,
                                peer_uuid,
                                std::move(cmeta)));
}

RaftConsensus::~RaftConsensus() {
  Shutdown();
}

Status RaftConsensus::Start(const ConsensusBootstrapInfo& info) {
  // This just starts the monitor thread -- no failure detector is registered yet.
  if (FLAGS_enable_leader_failure_detection) {
    RETURN_NOT_OK(failure_monitor_.Start());
  }

  // Register the failure detector instance with the monitor.
  // We still have not enabled failure detection for the leader election timer.
  // That happens separately via the helper functions
  // EnsureFailureDetector(Enabled/Disabled)Unlocked();
  RETURN_NOT_OK(failure_monitor_.MonitorFailureDetector(state_->GetOptions().tablet_id,
                                                        failure_detector_));

  {
    ReplicaState::UniqueLock lock;
    RETURN_NOT_OK(state_->LockForStart(&lock));
    state_->ClearLeaderUnlocked();

    RETURN_NOT_OK_PREPEND(state_->StartUnlocked(info.last_id),
                          "Unable to start Raft ReplicaState");

    LOG_WITH_PREFIX_UNLOCKED(INFO) << "Replica starting. Triggering "
                                   << info.orphaned_replicates.size()
                                   << " pending transactions. Active config: "
                                   << SecureShortDebugString(state_->GetActiveConfigUnlocked());
    for (ReplicateMsg* replicate : info.orphaned_replicates) {
      ReplicateRefPtr replicate_ptr = make_scoped_refptr_replicate(new ReplicateMsg(*replicate));
      RETURN_NOT_OK(StartReplicaTransactionUnlocked(replicate_ptr));
    }

    pending_.SetInitialCommittedOpId(info.last_committed_id);

    queue_->Init(info.last_id, info.last_committed_id);
  }

  {
    ReplicaState::UniqueLock lock;
    RETURN_NOT_OK(state_->LockForConfigChange(&lock));

    RETURN_NOT_OK(EnsureFailureDetectorEnabledUnlocked());

    // If this is the first term expire the FD immediately so that we have a fast first
    // election, otherwise we just let the timer expire normally.
    if (state_->GetCurrentTermUnlocked() == 0) {
      // Initialize the failure detector timeout to some time in the past so that
      // the next time the failure detector monitor runs it triggers an election
      // (unless someone else requested a vote from us first, which resets the
      // election timer). We do it this way instead of immediately running an
      // election to get a higher likelihood of enough servers being available
      // when the first one attempts an election to avoid multiple election
      // cycles on startup, while keeping that "waiting period" random.
      if (PREDICT_TRUE(FLAGS_enable_leader_failure_detection)) {
        LOG_WITH_PREFIX_UNLOCKED(INFO) << "Consensus starting up: Expiring failure detector timer "
                                          "to make a prompt election more likely";
      }
      RETURN_NOT_OK(ExpireFailureDetectorUnlocked());
    }

    // Now assume "follower" duties.
    RETURN_NOT_OK(BecomeReplicaUnlocked());
  }

  bool single_voter = false;
  RETURN_NOT_OK(IsSingleVoterConfig(&single_voter));
  if (single_voter && FLAGS_enable_leader_failure_detection) {
    LOG_WITH_PREFIX(INFO) << "Only one voter in the Raft config. Triggering election immediately";
    RETURN_NOT_OK(StartElection(NORMAL_ELECTION, INITIAL_SINGLE_NODE_ELECTION));
  }

  // Report become visible to the Master.
  MarkDirty("RaftConsensus started");

  return Status::OK();
}

bool RaftConsensus::IsRunning() const {
  ReplicaState::UniqueLock lock;
  Status s = state_->LockForRead(&lock);
  if (PREDICT_FALSE(!s.ok())) return false;
  return state_->state() == ReplicaState::kRunning;
}

Status RaftConsensus::EmulateElection() {
  ReplicaState::UniqueLock lock;
  RETURN_NOT_OK(state_->LockForConfigChange(&lock));

  LOG_WITH_PREFIX_UNLOCKED(INFO) << "Emulating election...";

  // Assume leadership of new term.
  RETURN_NOT_OK(HandleTermAdvanceUnlocked(state_->GetCurrentTermUnlocked() + 1));
  SetLeaderUuidUnlocked(state_->GetPeerUuid());
  return BecomeLeaderUnlocked();
}

namespace {
const char* ModeString(Consensus::ElectionMode mode) {
  switch (mode) {
    case Consensus::NORMAL_ELECTION:
      return "leader election";
    case Consensus::PRE_ELECTION:
      return "pre-election";
    case Consensus::ELECT_EVEN_IF_LEADER_IS_ALIVE:
      return "forced leader election";
  }
  __builtin_unreachable(); // silence gcc warnings
}
string ReasonString(Consensus::ElectionReason reason, StringPiece leader_uuid) {
  switch (reason) {
    case Consensus::INITIAL_SINGLE_NODE_ELECTION:
      return "initial election of a single-replica configuration";
    case Consensus::EXTERNAL_REQUEST:
      return "received explicit request";
    case Consensus::ELECTION_TIMEOUT_EXPIRED:
      if (leader_uuid.empty()) {
        return "no leader contacted us within the election timeout";
      }
      return Substitute("detected failure of leader $0", leader_uuid);
  }
  __builtin_unreachable(); // silence gcc warnings
}
} // anonymous namespace

Status RaftConsensus::StartElection(ElectionMode mode, ElectionReason reason) {
  const char* mode_str = ModeString(mode);

  TRACE_EVENT2("consensus", "RaftConsensus::StartElection",
               "peer", state_->LogPrefixThreadSafe(),
               "mode", mode_str);
  scoped_refptr<LeaderElection> election;
  {
    ReplicaState::UniqueLock lock;
    RETURN_NOT_OK(state_->LockForConfigChange(&lock));

    RaftPeerPB::Role active_role = state_->GetActiveRoleUnlocked();
    if (active_role == RaftPeerPB::LEADER) {
      LOG_WITH_PREFIX_UNLOCKED(INFO) << "Not starting " << mode << " -- already leader";
      return Status::OK();
    }
    if (PREDICT_FALSE(active_role == RaftPeerPB::NON_PARTICIPANT)) {
      SnoozeFailureDetectorUnlocked(); // Avoid excessive election noise while in this state.
      return Status::IllegalState("Not starting election: Node is currently "
                                  "a non-participant in the raft config",
                                  SecureShortDebugString(state_->GetActiveConfigUnlocked()));
    }
    LOG_WITH_PREFIX_UNLOCKED(INFO)
        << "Starting " << mode_str
        << " (" << ReasonString(reason, state_->GetLeaderUuidUnlocked()) << ")";

    // Snooze to avoid the election timer firing again as much as possible.
    // We do not disable the election timer while running an election, so that
    // if the election times out, we will try again.
    RETURN_NOT_OK(EnsureFailureDetectorEnabledUnlocked());

    MonoDelta timeout = LeaderElectionExpBackoffDeltaUnlocked();
    RETURN_NOT_OK(SnoozeFailureDetectorUnlocked(timeout, ALLOW_LOGGING));

    // Increment the term and vote for ourselves, unless it's a pre-election.
    if (mode != PRE_ELECTION) {
      // TODO(mpercy): Consider using a separate Mutex for voting, which must sync to disk.

      // We skip flushing the term to disk because setting the vote just below also
      // flushes to disk, and the double fsync doesn't buy us anything.
      RETURN_NOT_OK(HandleTermAdvanceUnlocked(state_->GetCurrentTermUnlocked() + 1,
                                              ReplicaState::SKIP_FLUSH_TO_DISK));
      RETURN_NOT_OK(state_->SetVotedForCurrentTermUnlocked(state_->GetPeerUuid()));
    }

    const RaftConfigPB& active_config = state_->GetActiveConfigUnlocked();
    LOG_WITH_PREFIX_UNLOCKED(INFO) << "Starting " << mode_str << " with config: "
                                   << SecureShortDebugString(active_config);

    // Initialize the VoteCounter.
    int num_voters = CountVoters(active_config);
    int majority_size = MajoritySize(num_voters);
    gscoped_ptr<VoteCounter> counter(new VoteCounter(num_voters, majority_size));

    // Vote for ourselves.
    bool duplicate;
    RETURN_NOT_OK(counter->RegisterVote(state_->GetPeerUuid(), VOTE_GRANTED, &duplicate));
    CHECK(!duplicate) << state_->LogPrefixUnlocked()
                      << "Inexplicable duplicate self-vote for term "
                      << state_->GetCurrentTermUnlocked();

    VoteRequestPB request;
    request.set_ignore_live_leader(mode == ELECT_EVEN_IF_LEADER_IS_ALIVE);
    request.set_candidate_uuid(state_->GetPeerUuid());
    if (mode == PRE_ELECTION) {
      // In a pre-election, we haven't bumped our own term yet, so we need to be
      // asking for votes for the next term.
      request.set_is_pre_election(true);
      request.set_candidate_term(state_->GetCurrentTermUnlocked() + 1);
    } else {
      request.set_candidate_term(state_->GetCurrentTermUnlocked());
    }
    request.set_tablet_id(state_->GetOptions().tablet_id);
    *request.mutable_candidate_status()->mutable_last_received() =
        queue_->GetLastOpIdInLog();

    election.reset(new LeaderElection(active_config,
                                      peer_proxy_factory_.get(),
                                      request, std::move(counter), timeout,
                                      Bind(&RaftConsensus::ElectionCallback, this, reason)));
  }

  // Start the election outside the lock.
  election->Run();

  return Status::OK();
}

Status RaftConsensus::WaitUntilLeaderForTests(const MonoDelta& timeout) {
  MonoTime deadline = MonoTime::Now() + timeout;
  while (role() != consensus::RaftPeerPB::LEADER) {
    if (MonoTime::Now() >= deadline) {
      return Status::TimedOut(Substitute("Peer $0 is not leader of tablet $1 after $2. Role: $3",
                                         peer_uuid(), tablet_id(), timeout.ToString(), role()));
    }
    SleepFor(MonoDelta::FromMilliseconds(10));
  }
  return Status::OK();
}

Status RaftConsensus::StepDown(LeaderStepDownResponsePB* resp) {
  TRACE_EVENT0("consensus", "RaftConsensus::StepDown");
  ReplicaState::UniqueLock lock;
  RETURN_NOT_OK(state_->LockForConfigChange(&lock));
  if (state_->GetActiveRoleUnlocked() != RaftPeerPB::LEADER) {
    resp->mutable_error()->set_code(TabletServerErrorPB::NOT_THE_LEADER);
    StatusToPB(Status::IllegalState("Not currently leader"),
               resp->mutable_error()->mutable_status());
    // We return OK so that the tablet service won't overwrite the error code.
    return Status::OK();
  }
  RETURN_NOT_OK(BecomeReplicaUnlocked());
  return Status::OK();
}

void RaftConsensus::ReportFailureDetected(const std::string& name, const Status& /*msg*/) {
  DCHECK_EQ(name, kTimerId);
  // Start an election.
  Status s = StartElection(FLAGS_raft_enable_pre_election ? PRE_ELECTION : NORMAL_ELECTION,
                           ELECTION_TIMEOUT_EXPIRED);
  if (PREDICT_FALSE(!s.ok())) {
    LOG_WITH_PREFIX(WARNING) << "Failed to trigger leader election: " << s.ToString();
  }
}

Status RaftConsensus::BecomeLeaderUnlocked() {
  TRACE_EVENT2("consensus", "RaftConsensus::BecomeLeaderUnlocked",
               "peer", peer_uuid(),
               "tablet", tablet_id());
  LOG_WITH_PREFIX_UNLOCKED(INFO) << "Becoming Leader. State: " << state_->ToStringUnlocked();

  // Disable FD while we are leader.
  RETURN_NOT_OK(EnsureFailureDetectorDisabledUnlocked());

  // Don't vote for anyone if we're a leader.
  withhold_votes_until_ = MonoTime::Max();

  queue_->RegisterObserver(this);
  RETURN_NOT_OK(RefreshConsensusQueueAndPeersUnlocked());

  // Initiate a NO_OP transaction that is sent at the beginning of every term
  // change in raft.
  auto replicate = new ReplicateMsg;
  replicate->set_op_type(NO_OP);
  replicate->mutable_noop_request(); // Define the no-op request field.
  CHECK_OK(time_manager_->AssignTimestamp(replicate));

  scoped_refptr<ConsensusRound> round(
      new ConsensusRound(this, make_scoped_refptr(new RefCountedReplicate(replicate))));
  round->SetConsensusReplicatedCallback(Bind(&RaftConsensus::NonTxRoundReplicationFinished,
                                             Unretained(this),
                                             Unretained(round.get()),
                                             Bind(&DoNothingStatusCB)));
  RETURN_NOT_OK(AppendNewRoundToQueueUnlocked(round));

  return Status::OK();
}

Status RaftConsensus::BecomeReplicaUnlocked() {
  LOG_WITH_PREFIX_UNLOCKED(INFO) << "Becoming Follower/Learner. State: "
                                 << state_->ToStringUnlocked();

  state_->ClearLeaderUnlocked();

  // FD should be running while we are a follower.
  RETURN_NOT_OK(EnsureFailureDetectorEnabledUnlocked());

  // Now that we're a replica, we can allow voting for other nodes.
  withhold_votes_until_ = MonoTime::Min();

  queue_->UnRegisterObserver(this);
  // Deregister ourselves from the queue. We don't care what get's replicated, since
  // we're stepping down.
  queue_->SetNonLeaderMode();

  peer_manager_->Close();
  return Status::OK();
}

Status RaftConsensus::Replicate(const scoped_refptr<ConsensusRound>& round) {

  std::lock_guard<simple_spinlock> lock(update_lock_);
  {
    ReplicaState::UniqueLock lock;
    RETURN_NOT_OK(state_->LockForReplicate(&lock, *round->replicate_msg()));
    RETURN_NOT_OK(round->CheckBoundTerm(state_->GetCurrentTermUnlocked()));
    RETURN_NOT_OK(AppendNewRoundToQueueUnlocked(round));
  }

  peer_manager_->SignalRequest();
  return Status::OK();
}

Status RaftConsensus::CheckLeadershipAndBindTerm(const scoped_refptr<ConsensusRound>& round) {
  ReplicaState::UniqueLock lock;
  RETURN_NOT_OK(state_->LockForReplicate(&lock, *round->replicate_msg()));
  round->BindToTerm(state_->GetCurrentTermUnlocked());
  return Status::OK();
}

Status RaftConsensus::AppendNewRoundToQueueUnlocked(const scoped_refptr<ConsensusRound>& round) {
  *round->replicate_msg()->mutable_id() = queue_->GetNextOpId();
  RETURN_NOT_OK(AddPendingOperationUnlocked(round));

  // The only reasons for a bad status would be if the log itself were shut down,
  // or if we had an actual IO error, which we currently don't handle.
  CHECK_OK_PREPEND(queue_->AppendOperation(round->replicate_scoped_refptr()),
                   Substitute("$0: could not append to queue", LogPrefixUnlocked()));
  return Status::OK();
}

Status RaftConsensus::AddPendingOperationUnlocked(const scoped_refptr<ConsensusRound>& round) {
  // If we are adding a pending config change, we need to propagate it to the
  // metadata.
  if (PREDICT_FALSE(round->replicate_msg()->op_type() == CHANGE_CONFIG_OP)) {
    // Fill in the opid for the proposed new configuration. This has to be done
    // here rather than when it's first created because we didn't yet have an
    // OpId assigned at creation time.
    ChangeConfigRecordPB* change_record = round->replicate_msg()->mutable_change_config_record();
    change_record->mutable_new_config()->set_opid_index(round->replicate_msg()->id().index());

    DCHECK(change_record->IsInitialized())
        << "change_config_record missing required fields: "
        << change_record->InitializationErrorString();

    const RaftConfigPB& new_config = change_record->new_config();

    if (!new_config.unsafe_config_change()) {
      Status s = state_->CheckNoConfigChangePendingUnlocked();
      if (PREDICT_FALSE(!s.ok())) {
        s = s.CloneAndAppend(Substitute("\n  New config: $0", SecureShortDebugString(new_config)));
        LOG_WITH_PREFIX_UNLOCKED(INFO) << s.ToString();
        return s;
      }
    }
    // Check if the pending Raft config has an OpId less than the committed
    // config. If so, this is a replay at startup in which the COMMIT
    // messages were delayed.
    const RaftConfigPB& committed_config = state_->GetCommittedConfigUnlocked();
    if (round->replicate_msg()->id().index() > committed_config.opid_index()) {
      RETURN_NOT_OK(state_->SetPendingConfigUnlocked(new_config));
      if (state_->GetActiveRoleUnlocked() == RaftPeerPB::LEADER) {
        RETURN_NOT_OK(RefreshConsensusQueueAndPeersUnlocked());
      }
    } else {
      LOG_WITH_PREFIX_UNLOCKED(INFO)
          << "Ignoring setting pending config change with OpId "
          << round->replicate_msg()->id() << " because the committed config has OpId index "
          << committed_config.opid_index() << ". The config change we are ignoring is: "
          << "Old config: { " << SecureShortDebugString(change_record->old_config()) << " }. "
          << "New config: { " << SecureShortDebugString(new_config) << " }";
    }
  }

  return pending_.AddPendingOperation(round);
}

void RaftConsensus::NotifyCommitIndex(int64_t commit_index) {
  ReplicaState::UniqueLock lock;
  Status s = state_->LockForCommit(&lock);
  if (PREDICT_FALSE(!s.ok())) {
    LOG_WITH_PREFIX(WARNING)
        << "Unable to take state lock to update committed index: "
        << s.ToString();
    return;
  }

  pending_.AdvanceCommittedIndex(commit_index);

  if (state_->GetActiveRoleUnlocked() == RaftPeerPB::LEADER) {
    peer_manager_->SignalRequest(false);
  }
}

void RaftConsensus::NotifyTermChange(int64_t term) {
  ReplicaState::UniqueLock lock;
  Status s = state_->LockForConfigChange(&lock);
  if (PREDICT_FALSE(!s.ok())) {
    LOG(WARNING) << state_->LogPrefixThreadSafe() << "Unable to lock ReplicaState for term change"
                 << " when notified of new term " << term << ": " << s.ToString();
    return;
  }
  WARN_NOT_OK(HandleTermAdvanceUnlocked(term), "Couldn't advance consensus term.");
}

void RaftConsensus::NotifyFailedFollower(const string& uuid,
                                         int64_t term,
                                         const std::string& reason) {
  // Common info used in all of the log messages within this method.
  string fail_msg = Substitute("Processing failure of peer $0 in term $1 ($2): ",
                               uuid, term, reason);

  if (!FLAGS_evict_failed_followers) {
    LOG(INFO) << state_->LogPrefixThreadSafe() << fail_msg
              << "Eviction of failed followers is disabled. Doing nothing.";
    return;
  }

  RaftConfigPB committed_config;
  {
    ReplicaState::UniqueLock lock;
    Status s = state_->LockForRead(&lock);
    if (PREDICT_FALSE(!s.ok())) {
      LOG(WARNING) << state_->LogPrefixThreadSafe() << fail_msg
                   << "Unable to lock ReplicaState for read: " << s.ToString();
      return;
    }

    int64_t current_term = state_->GetCurrentTermUnlocked();
    if (current_term != term) {
      LOG_WITH_PREFIX_UNLOCKED(INFO) << fail_msg << "Notified about a follower failure in "
                                     << "previous term " << term << ", but a leader election "
                                     << "likely occurred since the failure was detected. "
                                     << "Doing nothing.";
      return;
    }

    if (state_->IsConfigChangePendingUnlocked()) {
      LOG_WITH_PREFIX_UNLOCKED(INFO) << fail_msg << "There is already a config change operation "
                                     << "in progress. Unable to evict follower until it completes. "
                                     << "Doing nothing.";
      return;
    }
    committed_config = state_->GetCommittedConfigUnlocked();
  }

  // Run config change on thread pool after dropping ReplicaState lock.
  WARN_NOT_OK(thread_pool_->SubmitClosure(Bind(&RaftConsensus::TryRemoveFollowerTask,
                                               this, uuid, committed_config, reason)),
              state_->LogPrefixThreadSafe() + "Unable to start RemoteFollowerTask");
}

void RaftConsensus::TryRemoveFollowerTask(const string& uuid,
                                          const RaftConfigPB& committed_config,
                                          const std::string& reason) {
  ChangeConfigRequestPB req;
  req.set_tablet_id(tablet_id());
  req.mutable_server()->set_permanent_uuid(uuid);
  req.set_type(REMOVE_SERVER);
  req.set_cas_config_opid_index(committed_config.opid_index());
  LOG(INFO) << state_->LogPrefixThreadSafe() << "Attempting to remove follower "
            << uuid << " from the Raft config. Reason: " << reason;
  boost::optional<TabletServerErrorPB::Code> error_code;
  WARN_NOT_OK(ChangeConfig(req, Bind(&DoNothingStatusCB), &error_code),
              state_->LogPrefixThreadSafe() + "Unable to remove follower " + uuid);
}

Status RaftConsensus::Update(const ConsensusRequestPB* request,
                             ConsensusResponsePB* response) {
  update_calls_for_tests_.Increment();

  if (PREDICT_FALSE(FLAGS_follower_reject_update_consensus_requests)) {
    return Status::IllegalState("Rejected: --follower_reject_update_consensus_requests "
                                "is set to true.");
  }

  response->set_responder_uuid(state_->GetPeerUuid());

  VLOG_WITH_PREFIX(2) << "Replica received request: " << SecureShortDebugString(*request);

  // see var declaration
  std::lock_guard<simple_spinlock> lock(update_lock_);
  Status s = UpdateReplica(request, response);
  if (PREDICT_FALSE(VLOG_IS_ON(1))) {
    if (request->ops_size() == 0) {
      VLOG_WITH_PREFIX(1) << "Replica replied to status only request. Replica: "
                          << state_->ToString() << ". Response: "
                          << SecureShortDebugString(*response);
    }
  }
  return s;
}

// Helper function to check if the op is a non-Transaction op.
static bool IsConsensusOnlyOperation(OperationType op_type) {
  return op_type == NO_OP || op_type == CHANGE_CONFIG_OP;
}

Status RaftConsensus::StartReplicaTransactionUnlocked(const ReplicateRefPtr& msg) {
  if (IsConsensusOnlyOperation(msg->get()->op_type())) {
    return StartConsensusOnlyRoundUnlocked(msg);
  }

  if (PREDICT_FALSE(FLAGS_follower_fail_all_prepare)) {
    return Status::IllegalState("Rejected: --follower_fail_all_prepare "
                                "is set to true.");
  }

  VLOG_WITH_PREFIX_UNLOCKED(1) << "Starting transaction: "
                               << SecureShortDebugString(msg->get()->id());
  scoped_refptr<ConsensusRound> round(new ConsensusRound(this, msg));
  ConsensusRound* round_ptr = round.get();
  RETURN_NOT_OK(txn_factory_->StartReplicaTransaction(round));
  return AddPendingOperationUnlocked(round_ptr);
}

Status RaftConsensus::IsSingleVoterConfig(bool* single_voter) const {
  ReplicaState::UniqueLock lock;
  RETURN_NOT_OK(state_->LockForRead(&lock));
  const RaftConfigPB& config = state_->GetCommittedConfigUnlocked();
  const string& uuid = state_->GetPeerUuid();
  if (CountVoters(config) == 1 && IsRaftConfigVoter(uuid, config)) {
    *single_voter = true;
  } else {
    *single_voter = false;
  }
  return Status::OK();
}

std::string RaftConsensus::LeaderRequest::OpsRangeString() const {
  std::string ret;
  ret.reserve(100);
  ret.push_back('[');
  if (!messages.empty()) {
    const OpId& first_op = (*messages.begin())->get()->id();
    const OpId& last_op = (*messages.rbegin())->get()->id();
    strings::SubstituteAndAppend(&ret, "$0.$1-$2.$3",
                                 first_op.term(), first_op.index(),
                                 last_op.term(), last_op.index());
  }
  ret.push_back(']');
  return ret;
}

void RaftConsensus::DeduplicateLeaderRequestUnlocked(ConsensusRequestPB* rpc_req,
                                                     LeaderRequest* deduplicated_req) {
  // TODO(todd): use queue committed index?
  int64_t last_committed_index = pending_.GetCommittedIndex();

  // The leader's preceding id.
  deduplicated_req->preceding_opid = &rpc_req->preceding_id();

  int64_t dedup_up_to_index = queue_->GetLastOpIdInLog().index();

  deduplicated_req->first_message_idx = -1;

  // In this loop we discard duplicates and advance the leader's preceding id
  // accordingly.
  for (int i = 0; i < rpc_req->ops_size(); i++) {
    ReplicateMsg* leader_msg = rpc_req->mutable_ops(i);

    if (leader_msg->id().index() <= last_committed_index) {
      VLOG_WITH_PREFIX_UNLOCKED(2) << "Skipping op id " << leader_msg->id()
                                   << " (already committed)";
      deduplicated_req->preceding_opid = &leader_msg->id();
      continue;
    }

    if (leader_msg->id().index() <= dedup_up_to_index) {
      // If the index is uncommitted and below our match index, then it must be in the
      // pendings set.
      scoped_refptr<ConsensusRound> round =
          pending_.GetPendingOpByIndexOrNull(leader_msg->id().index());
      DCHECK(round) << "Could not find op with index " << leader_msg->id().index()
                    << " in pending set. committed= " << last_committed_index
                    << " dedup=" << dedup_up_to_index;

      // If the OpIds match, i.e. if they have the same term and id, then this is just
      // duplicate, we skip...
      if (OpIdEquals(round->replicate_msg()->id(), leader_msg->id())) {
        VLOG_WITH_PREFIX_UNLOCKED(2) << "Skipping op id " << leader_msg->id()
                                     << " (already replicated)";
        deduplicated_req->preceding_opid = &leader_msg->id();
        continue;
      }

      // ... otherwise we must adjust our match index, i.e. all messages from now on
      // are "new"
      dedup_up_to_index = leader_msg->id().index();
    }

    if (deduplicated_req->first_message_idx == - 1) {
      deduplicated_req->first_message_idx = i;
    }
    deduplicated_req->messages.push_back(make_scoped_refptr_replicate(leader_msg));
  }

  if (deduplicated_req->messages.size() != rpc_req->ops_size()) {
    LOG_WITH_PREFIX_UNLOCKED(INFO) << "Deduplicated request from leader. Original: "
                          << rpc_req->preceding_id() << "->" << OpsRangeString(*rpc_req)
                          << "   Dedup: " << *deduplicated_req->preceding_opid << "->"
                          << deduplicated_req->OpsRangeString();
  }

}

Status RaftConsensus::HandleLeaderRequestTermUnlocked(const ConsensusRequestPB* request,
                                                      ConsensusResponsePB* response) {
  // Do term checks first:
  if (PREDICT_FALSE(request->caller_term() != state_->GetCurrentTermUnlocked())) {

    // If less, reject.
    if (request->caller_term() < state_->GetCurrentTermUnlocked()) {
      string msg = Substitute("Rejecting Update request from peer $0 for earlier term $1. "
                              "Current term is $2. Ops: $3",

                              request->caller_uuid(),
                              request->caller_term(),
                              state_->GetCurrentTermUnlocked(),
                              OpsRangeString(*request));
      LOG_WITH_PREFIX_UNLOCKED(INFO) << msg;
      FillConsensusResponseError(response,
                                 ConsensusErrorPB::INVALID_TERM,
                                 Status::IllegalState(msg));
      return Status::OK();
    }
    RETURN_NOT_OK(HandleTermAdvanceUnlocked(request->caller_term()));
  }
  return Status::OK();
}

Status RaftConsensus::EnforceLogMatchingPropertyMatchesUnlocked(const LeaderRequest& req,
                                                                ConsensusResponsePB* response) {

  bool term_mismatch;
  if (pending_.IsOpCommittedOrPending(*req.preceding_opid, &term_mismatch)) {
    return Status::OK();
  }

  string error_msg = Substitute(
    "Log matching property violated."
    " Preceding OpId in replica: $0. Preceding OpId from leader: $1. ($2 mismatch)",
    SecureShortDebugString(queue_->GetLastOpIdInLog()),
    SecureShortDebugString(*req.preceding_opid),
    term_mismatch ? "term" : "index");


  FillConsensusResponseError(response,
                             ConsensusErrorPB::PRECEDING_ENTRY_DIDNT_MATCH,
                             Status::IllegalState(error_msg));

  LOG_WITH_PREFIX_UNLOCKED(INFO) << "Refusing update from remote peer "
                        << req.leader_uuid << ": " << error_msg;

  // If the terms mismatch we abort down to the index before the leader's preceding,
  // since we know that is the last opid that has a chance of not being overwritten.
  // Aborting preemptively here avoids us reporting a last received index that is
  // possibly higher than the leader's causing an avoidable cache miss on the leader's
  // queue.
  //
  // TODO: this isn't just an optimization! if we comment this out, we get
  // failures on raft_consensus-itest a couple percent of the time! Should investigate
  // why this is actually critical to do here, as opposed to just on requests that
  // append some ops.
  if (term_mismatch) {
    TruncateAndAbortOpsAfterUnlocked(req.preceding_opid->index() - 1);
  }

  return Status::OK();
}

void RaftConsensus::TruncateAndAbortOpsAfterUnlocked(int64_t truncate_after_index) {
  pending_.AbortOpsAfter(truncate_after_index);
  queue_->TruncateOpsAfter(truncate_after_index);
}

Status RaftConsensus::CheckLeaderRequestUnlocked(const ConsensusRequestPB* request,
                                                 ConsensusResponsePB* response,
                                                 LeaderRequest* deduped_req) {

  if (request->has_deprecated_committed_index() ||
      !request->has_all_replicated_index()) {
    return Status::InvalidArgument("Leader appears to be running an earlier version "
                                   "of Kudu. Please shut down and upgrade all servers "
                                   "before restarting.");
  }

  ConsensusRequestPB* mutable_req = const_cast<ConsensusRequestPB*>(request);
  DeduplicateLeaderRequestUnlocked(mutable_req, deduped_req);

  // This is an additional check for KUDU-639 that makes sure the message's index
  // and term are in the right sequence in the request, after we've deduplicated
  // them. We do this before we change any of the internal state.
  //
  // TODO move this to raft_consensus-state or whatever we transform that into.
  // We should be able to do this check for each append, but right now the way
  // we initialize raft_consensus-state is preventing us from doing so.
  Status s;
  const OpId* prev = deduped_req->preceding_opid;
  for (const ReplicateRefPtr& message : deduped_req->messages) {
    s = PendingRounds::CheckOpInSequence(*prev, message->get()->id());
    if (PREDICT_FALSE(!s.ok())) {
      LOG(ERROR) << "Leader request contained out-of-sequence messages. Status: "
          << s.ToString() << ". Leader Request: " << SecureShortDebugString(*request);
      break;
    }
    prev = &message->get()->id();
  }

  // We only release the messages from the request after the above check so that
  // that we can print the original request, if it fails.
  if (!deduped_req->messages.empty()) {
    // We take ownership of the deduped ops.
    DCHECK_GE(deduped_req->first_message_idx, 0);
    mutable_req->mutable_ops()->ExtractSubrange(
        deduped_req->first_message_idx,
        deduped_req->messages.size(),
        nullptr);
  }

  RETURN_NOT_OK(s);

  RETURN_NOT_OK(HandleLeaderRequestTermUnlocked(request, response));

  if (response->status().has_error()) {
    return Status::OK();
  }

  RETURN_NOT_OK(EnforceLogMatchingPropertyMatchesUnlocked(*deduped_req, response));

  if (response->status().has_error()) {
    return Status::OK();
  }

  // If the first of the messages to apply is not in our log, either it follows the last
  // received message or it replaces some in-flight.
  if (!deduped_req->messages.empty()) {

    bool term_mismatch;
    CHECK(!pending_.IsOpCommittedOrPending(deduped_req->messages[0]->get()->id(), &term_mismatch));

    // If the index is in our log but the terms are not the same abort down to the leader's
    // preceding id.
    if (term_mismatch) {
      TruncateAndAbortOpsAfterUnlocked(deduped_req->preceding_opid->index());
    }
  }

  // If all of the above logic was successful then we can consider this to be
  // the effective leader of the configuration. If they are not currently marked as
  // the leader locally, mark them as leader now.
  const string& caller_uuid = request->caller_uuid();
  if (PREDICT_FALSE(state_->HasLeaderUnlocked() &&
                    state_->GetLeaderUuidUnlocked() != caller_uuid)) {
    LOG_WITH_PREFIX_UNLOCKED(FATAL) << "Unexpected new leader in same term! "
        << "Existing leader UUID: " << state_->GetLeaderUuidUnlocked() << ", "
        << "new leader UUID: " << caller_uuid;
  }
  if (PREDICT_FALSE(!state_->HasLeaderUnlocked())) {
    SetLeaderUuidUnlocked(request->caller_uuid());
  }

  return Status::OK();
}

Status RaftConsensus::UpdateReplica(const ConsensusRequestPB* request,
                                    ConsensusResponsePB* response) {
  TRACE_EVENT2("consensus", "RaftConsensus::UpdateReplica",
               "peer", peer_uuid(),
               "tablet", tablet_id());
  Synchronizer log_synchronizer;
  StatusCallback sync_status_cb = log_synchronizer.AsStatusCallback();


  // The ordering of the following operations is crucial, read on for details.
  //
  // The main requirements explained in more detail below are:
  //
  //   1) We must enqueue the prepares before we write to our local log.
  //   2) If we were able to enqueue a prepare then we must be able to log it.
  //   3) If we fail to enqueue a prepare, we must not attempt to enqueue any
  //      later-indexed prepare or apply.
  //
  // See below for detailed rationale.
  //
  // The steps are:
  //
  // 0 - Split/Dedup
  //
  // We split the operations into replicates and commits and make sure that we don't
  // don't do anything on operations we've already received in a previous call.
  // This essentially makes this method idempotent.
  //
  // 1 - We mark as many pending transactions as committed as we can.
  //
  // We may have some pending transactions that, according to the leader, are now
  // committed. We Apply them early, because:
  // - Soon (step 2) we may reject the call due to excessive memory pressure. One
  //   way to relieve the pressure is by flushing the MRS, and applying these
  //   transactions may unblock an in-flight Flush().
  // - The Apply and subsequent Prepares (step 2) can take place concurrently.
  //
  // 2 - We enqueue the Prepare of the transactions.
  //
  // The actual prepares are enqueued in order but happen asynchronously so we don't
  // have decoding/acquiring locks on the critical path.
  //
  // We need to do this now for a number of reasons:
  // - Prepares, by themselves, are inconsequential, i.e. they do not mutate the
  //   state machine so, were we to crash afterwards, having the prepares in-flight
  //   won't hurt.
  // - Prepares depend on factors external to consensus (the transaction drivers and
  //   the tablet peer) so if for some reason they cannot be enqueued we must know
  //   before we try write them to the WAL. Once enqueued, we assume that prepare will
  //   always succeed on a replica transaction (because the leader already prepared them
  //   successfully, and thus we know they are valid).
  // - The prepares corresponding to every operation that was logged must be in-flight
  //   first. This because should we need to abort certain transactions (say a new leader
  //   says they are not committed) we need to have those prepares in-flight so that
  //   the transactions can be continued (in the abort path).
  // - Failure to enqueue prepares is OK, we can continue and let the leader know that
  //   we only went so far. The leader will re-send the remaining messages.
  // - Prepares represent new transactions, and transactions consume memory. Thus, if the
  //   overall memory pressure on the server is too high, we will reject the prepares.
  //
  // 3 - We enqueue the writes to the WAL.
  //
  // We enqueue writes to the WAL, but only the operations that were successfully
  // enqueued for prepare (for the reasons introduced above). This means that even
  // if a prepare fails to enqueue, if any of the previous prepares were successfully
  // submitted they must be written to the WAL.
  // If writing to the WAL fails, we're in an inconsistent state and we crash. In this
  // case, no one will ever know of the transactions we previously prepared so those are
  // inconsequential.
  //
  // 4 - We mark the transactions as committed.
  //
  // For each transaction which has been committed by the leader, we update the
  // transaction state to reflect that. If the logging has already succeeded for that
  // transaction, this will trigger the Apply phase. Otherwise, Apply will be triggered
  // when the logging completes. In both cases the Apply phase executes asynchronously.
  // This must, of course, happen after the prepares have been triggered as the same batch
  // can both replicate/prepare and commit/apply an operation.
  //
  // Currently, if a prepare failed to enqueue we still trigger all applies for operations
  // with an id lower than it (if we have them). This is important now as the leader will
  // not re-send those commit messages. This will be moot when we move to the commit
  // commitIndex way of doing things as we can simply ignore the applies as we know
  // they will be triggered with the next successful batch.
  //
  // 5 - We wait for the writes to be durable.
  //
  // Before replying to the leader we wait for the writes to be durable. We then
  // just update the last replicated watermark and respond.
  //
  // TODO - These failure scenarios need to be exercised in an unit
  //        test. Moreover we need to add more fault injection spots (well that
  //        and actually use the) for each of these steps.
  //        This will be done in a follow up patch.
  TRACE("Updating replica for $0 ops", request->ops_size());

  // The deduplicated request.
  LeaderRequest deduped_req;

  {
    ReplicaState::UniqueLock lock;
    RETURN_NOT_OK(state_->LockForUpdate(&lock));

    deduped_req.leader_uuid = request->caller_uuid();

    RETURN_NOT_OK(CheckLeaderRequestUnlocked(request, response, &deduped_req));

    if (response->status().has_error()) {
      // We had an error, like an invalid term, we still fill the response.
      FillConsensusResponseOKUnlocked(response);
      return Status::OK();
    }

    // Snooze the failure detector as soon as we decide to accept the message.
    // We are guaranteed to be acting as a FOLLOWER at this point by the above
    // sanity check.
    RETURN_NOT_OK(SnoozeFailureDetectorUnlocked());

    // We update the lag metrics here in addition to after appending to the queue so the
    // metrics get updated even when the operation is rejected.
    queue_->UpdateLastIndexAppendedToLeader(request->last_idx_appended_to_leader());

    // Also prohibit voting for anyone for the minimum election timeout.
    withhold_votes_until_ = MonoTime::Now() + MinimumElectionTimeout();

    // 1 - Early commit pending (and committed) transactions

    // What should we commit?
    // 1. As many pending transactions as we can, except...
    // 2. ...if we commit beyond the preceding index, we'd regress KUDU-639, and...
    // 3. ...the leader's committed index is always our upper bound.
    int64_t early_apply_up_to = std::min<int64_t>({
        pending_.GetLastPendingTransactionOpId().index(),
        deduped_req.preceding_opid->index(),
        request->committed_index()});

    VLOG_WITH_PREFIX_UNLOCKED(1) << "Early marking committed up to " << early_apply_up_to
                                 << ", Last pending opid index: "
                                 << pending_.GetLastPendingTransactionOpId().index()
                                 << ", preceding opid index: "
                                 << deduped_req.preceding_opid->index()
                                 << ", requested index: " << request->committed_index();
    TRACE("Early marking committed up to index $0", early_apply_up_to);
    CHECK_OK(pending_.AdvanceCommittedIndex(early_apply_up_to));

    // 2 - Enqueue the prepares

    TRACE("Triggering prepare for $0 ops", deduped_req.messages.size());

    Status prepare_status;
    auto iter = deduped_req.messages.begin();

    if (PREDICT_TRUE(!deduped_req.messages.empty())) {

      // This request contains at least one message, and is likely to increase
      // our memory pressure.
      double capacity_pct;
      if (parent_mem_tracker_->AnySoftLimitExceeded(&capacity_pct)) {
        follower_memory_pressure_rejections_->Increment();
        string msg = StringPrintf(
            "Soft memory limit exceeded (at %.2f%% of capacity)",
            capacity_pct);
        if (capacity_pct >= FLAGS_memory_limit_warn_threshold_percentage) {
          KLOG_EVERY_N_SECS(WARNING, 1) << "Rejecting consensus request: " << msg
                                        << THROTTLE_MSG;
        } else {
          KLOG_EVERY_N_SECS(INFO, 1) << "Rejecting consensus request: " << msg
                                     << THROTTLE_MSG;
        }
        return Status::ServiceUnavailable(msg);
      }
    }

    while (iter != deduped_req.messages.end()) {
      prepare_status = StartReplicaTransactionUnlocked(*iter);
      if (PREDICT_FALSE(!prepare_status.ok())) {
        break;
      }
      // TODO(dralves) Without leader leases this shouldn't be a allowed to fail.
      // Once we have that functionality we'll have to revisit this.
      CHECK_OK(time_manager_->MessageReceivedFromLeader(*(*iter)->get()));
      ++iter;
    }

    // If we stopped before reaching the end we failed to prepare some message(s) and need
    // to perform cleanup, namely trimming deduped_req.messages to only contain the messages
    // that were actually prepared, and deleting the other ones since we've taken ownership
    // when we first deduped.
    if (iter != deduped_req.messages.end()) {
      bool need_to_warn = true;
      while (iter != deduped_req.messages.end()) {
        ReplicateRefPtr msg = (*iter);
        iter = deduped_req.messages.erase(iter);
        if (need_to_warn) {
          need_to_warn = false;
          LOG_WITH_PREFIX_UNLOCKED(WARNING) << "Could not prepare transaction for op: "
              << msg->get()->id() << ". Suppressed " << deduped_req.messages.size() <<
              " other warnings. Status for this op: " << prepare_status.ToString();
        }
      }

      // If this is empty, it means we couldn't prepare a single de-duped message. There is nothing
      // else we can do. The leader will detect this and retry later.
      if (deduped_req.messages.empty()) {
        string msg = Substitute("Rejecting Update request from peer $0 for term $1. "
                                "Could not prepare a single transaction due to: $2",
                                request->caller_uuid(),
                                request->caller_term(),
                                prepare_status.ToString());
        LOG_WITH_PREFIX_UNLOCKED(INFO) << msg;
        FillConsensusResponseError(response, ConsensusErrorPB::CANNOT_PREPARE,
                                   Status::IllegalState(msg));
        FillConsensusResponseOKUnlocked(response);
        return Status::OK();
      }
    }

    // All transactions that are going to be prepared were started, advance the safe timestamp.
    // TODO(dralves) This is only correct because the queue only sets safe time when the request is
    // an empty heartbeat. If we actually start setting this on a consensus request along with
    // actual messages we need to be careful to ignore it if any of the messages fails to prepare.
    if (request->has_safe_timestamp()) {
      time_manager_->AdvanceSafeTime(Timestamp(request->safe_timestamp()));
    }

    OpId last_from_leader;
    // 3 - Enqueue the writes.
    // Now that we've triggered the prepares enqueue the operations to be written
    // to the WAL.
    if (PREDICT_TRUE(!deduped_req.messages.empty())) {
      last_from_leader = deduped_req.messages.back()->get()->id();
      // Trigger the log append asap, if fsync() is on this might take a while
      // and we can't reply until this is done.
      //
      // Since we've prepared, we need to be able to append (or we risk trying to apply
      // later something that wasn't logged). We crash if we can't.
      CHECK_OK(queue_->AppendOperations(deduped_req.messages, sync_status_cb));
    } else {
      last_from_leader = *deduped_req.preceding_opid;
    }

    // 4 - Mark transactions as committed

    // Choose the last operation to be applied. This will either be 'committed_index', if
    // no prepare enqueuing failed, or the minimum between 'committed_index' and the id of
    // the last successfully enqueued prepare, if some prepare failed to enqueue.
    int64_t apply_up_to;
    if (last_from_leader.index() < request->committed_index()) {
      // we should never apply anything later than what we received in this request
      apply_up_to = last_from_leader.index();

      VLOG_WITH_PREFIX_UNLOCKED(2) << "Received commit index "
          << request->committed_index() << " from the leader but only"
          << " marked up to " << apply_up_to << " as committed.";
    } else {
      apply_up_to = request->committed_index();
    }

    VLOG_WITH_PREFIX_UNLOCKED(1) << "Marking committed up to " << apply_up_to;
    TRACE("Marking committed up to $0", apply_up_to);
    CHECK_OK(pending_.AdvanceCommittedIndex(apply_up_to));
    queue_->UpdateFollowerWatermarks(apply_up_to, request->all_replicated_index());

    // If any messages failed to be started locally, then we already have removed them
    // from 'deduped_req' at this point. So, 'last_from_leader' is the last one that
    // we might apply.
    last_received_cur_leader_ = last_from_leader;

    // Fill the response with the current state. We will not mutate anymore state until
    // we actually reply to the leader, we'll just wait for the messages to be durable.
    FillConsensusResponseOKUnlocked(response);
  }
  // Release the lock while we wait for the log append to finish so that commits can go through.
  // We'll re-acquire it before we update the state again.

  // Update the last replicated op id
  if (!deduped_req.messages.empty()) {

    // 5 - We wait for the writes to be durable.

    // Note that this is safe because dist consensus now only supports a single outstanding
    // request at a time and this way we can allow commits to proceed while we wait.
    TRACE("Waiting on the replicates to finish logging");
    TRACE_EVENT0("consensus", "Wait for log");
    Status s;
    do {
      s = log_synchronizer.WaitFor(
      MonoDelta::FromMilliseconds(FLAGS_raft_heartbeat_interval_ms));
      // If just waiting for our log append to finish lets snooze the timer.
      // We don't want to fire leader election because we're waiting on our own log.
      if (s.IsTimedOut()) {
        SnoozeFailureDetectorUnlocked();
      }
    } while (s.IsTimedOut());
    RETURN_NOT_OK(s);

    TRACE("finished");
  }

  VLOG_WITH_PREFIX(2) << "Replica updated. " << state_->ToString()
                      << ". Request: " << SecureShortDebugString(*request);

  TRACE("UpdateReplicas() finished");
  return Status::OK();
}

void RaftConsensus::FillConsensusResponseOKUnlocked(ConsensusResponsePB* response) {
  TRACE("Filling consensus response to leader.");
  response->set_responder_term(state_->GetCurrentTermUnlocked());
  response->mutable_status()->mutable_last_received()->CopyFrom(
      queue_->GetLastOpIdInLog());
  response->mutable_status()->mutable_last_received_current_leader()->CopyFrom(
      last_received_cur_leader_);
  response->mutable_status()->set_last_committed_idx(
      queue_->GetCommittedIndex());
}

void RaftConsensus::FillConsensusResponseError(ConsensusResponsePB* response,
                                               ConsensusErrorPB::Code error_code,
                                               const Status& status) {
  ConsensusErrorPB* error = response->mutable_status()->mutable_error();
  error->set_code(error_code);
  StatusToPB(status, error->mutable_status());
}

Status RaftConsensus::RequestVote(const VoteRequestPB* request, VoteResponsePB* response) {
  TRACE_EVENT2("consensus", "RaftConsensus::RequestVote",
               "peer", peer_uuid(),
               "tablet", tablet_id());
  response->set_responder_uuid(state_->GetPeerUuid());

  // We must acquire the update lock in order to ensure that this vote action
  // takes place between requests.
  // Lock ordering: The update lock must be acquired before the ReplicaState lock.
  std::unique_lock<simple_spinlock> update_guard(update_lock_, std::defer_lock);
  if (FLAGS_enable_leader_failure_detection) {
    update_guard.try_lock();
  } else {
    // If failure detection is not enabled, then we can't just reject the vote,
    // because there will be no automatic retry later. So, block for the lock.
    update_guard.lock();
  }
  if (!update_guard.owns_lock()) {
    // There is another vote or update concurrent with the vote. In that case, that
    // other request is likely to reset the timer, and we'll end up just voting
    // "NO" after waiting. To avoid starving RPC handlers and causing cascading
    // timeouts, just vote a quick NO.
    //
    // We still need to take the state lock in order to respond with term info, etc.
    ReplicaState::UniqueLock state_guard;
    RETURN_NOT_OK(state_->LockForConfigChange(&state_guard));
    return RequestVoteRespondIsBusy(request, response);
  }

  // Acquire the replica state lock so we can read / modify the consensus state.
  ReplicaState::UniqueLock state_guard;
  RETURN_NOT_OK(state_->LockForConfigChange(&state_guard));

  // If the node is not in the configuration, allow the vote (this is required by Raft)
  // but log an informational message anyway.
  if (!IsRaftConfigMember(request->candidate_uuid(), state_->GetActiveConfigUnlocked())) {
    LOG_WITH_PREFIX_UNLOCKED(INFO) << "Handling vote request from an unknown peer "
                                   << request->candidate_uuid();
  }

  // If we've heard recently from the leader, then we should ignore the request.
  // It might be from a "disruptive" server. This could happen in a few cases:
  //
  // 1) Network partitions
  // If the leader can talk to a majority of the nodes, but is partitioned from a
  // bad node, the bad node's failure detector will trigger. If the bad node is
  // able to reach other nodes in the cluster, it will continuously trigger elections.
  //
  // 2) An abandoned node
  // It's possible that a node has fallen behind the log GC mark of the leader. In that
  // case, the leader will stop sending it requests. Eventually, the the configuration
  // will change to eject the abandoned node, but until that point, we don't want the
  // abandoned follower to disturb the other nodes.
  //
  // See also https://ramcloud.stanford.edu/~ongaro/thesis.pdf
  // section 4.2.3.
  MonoTime now = MonoTime::Now();
  if (!request->ignore_live_leader() && now < withhold_votes_until_) {
    return RequestVoteRespondLeaderIsAlive(request, response);
  }

  // Candidate is running behind.
  if (request->candidate_term() < state_->GetCurrentTermUnlocked()) {
    return RequestVoteRespondInvalidTerm(request, response);
  }

  // We already voted this term.
  if (request->candidate_term() == state_->GetCurrentTermUnlocked() &&
      state_->HasVotedCurrentTermUnlocked()) {

    // Already voted for the same candidate in the current term.
    if (state_->GetVotedForCurrentTermUnlocked() == request->candidate_uuid()) {
      return RequestVoteRespondVoteAlreadyGranted(request, response);
    }

    // Voted for someone else in current term.
    return RequestVoteRespondAlreadyVotedForOther(request, response);
  }

  // Candidate must have last-logged OpId at least as large as our own to get
  // our vote.
  OpId local_last_logged_opid = GetLatestOpIdFromLog();
  bool vote_yes = !OpIdLessThan(request->candidate_status().last_received(),
                                local_last_logged_opid);

  // Record the term advancement if necessary. We don't do so in the case of
  // pre-elections because it's possible that the node who called the pre-election
  // has actually now successfully become leader of the prior term, in which case
  // bumping our term here would disrupt it.
  if (!request->is_pre_election() &&
      request->candidate_term() > state_->GetCurrentTermUnlocked()) {
    // If we are going to vote for this peer, then we will flush the consensus metadata
    // to disk below when we record the vote, and we can skip flushing the term advancement
    // to disk here.
    auto flush = vote_yes ? ReplicaState::SKIP_FLUSH_TO_DISK : ReplicaState::FLUSH_TO_DISK;
    RETURN_NOT_OK_PREPEND(HandleTermAdvanceUnlocked(request->candidate_term(), flush),
        Substitute("Could not step down in RequestVote. Current term: $0, candidate term: $1",
                   state_->GetCurrentTermUnlocked(), request->candidate_term()));
  }

  if (!vote_yes) {
    return RequestVoteRespondLastOpIdTooOld(local_last_logged_opid, request, response);
  }

  // Passed all our checks. Vote granted.
  return RequestVoteRespondVoteGranted(request, response);
}

Status RaftConsensus::ChangeConfig(const ChangeConfigRequestPB& req,
                                   const StatusCallback& client_cb,
                                   boost::optional<TabletServerErrorPB::Code>* error_code) {
  if (PREDICT_FALSE(!req.has_type())) {
    return Status::InvalidArgument("Must specify 'type' argument to ChangeConfig()",
                                   SecureShortDebugString(req));
  }
  if (PREDICT_FALSE(!req.has_server())) {
    *error_code = TabletServerErrorPB::INVALID_CONFIG;
    return Status::InvalidArgument("Must specify 'server' argument to ChangeConfig()",
                                   SecureShortDebugString(req));
  }
  ChangeConfigType type = req.type();
  const RaftPeerPB& server = req.server();
  {
    ReplicaState::UniqueLock lock;
    RETURN_NOT_OK(state_->LockForConfigChange(&lock));
    RETURN_NOT_OK(state_->CheckActiveLeaderUnlocked());
    RETURN_NOT_OK(state_->CheckNoConfigChangePendingUnlocked());

    // We are required by Raft to reject config change operations until we have
    // committed at least one operation in our current term as leader.
    // See https://groups.google.com/forum/#!topic/raft-dev/t4xj6dJTP6E
    if (!queue_->IsCommittedIndexInCurrentTerm()) {
      return Status::IllegalState("Leader has not yet committed an operation in its own term");
    }

    if (!server.has_permanent_uuid()) {
      return Status::InvalidArgument("server must have permanent_uuid specified",
                                     SecureShortDebugString(req));
    }
    const RaftConfigPB& committed_config = state_->GetCommittedConfigUnlocked();

    // Support atomic ChangeConfig requests.
    if (req.has_cas_config_opid_index()) {
      if (committed_config.opid_index() != req.cas_config_opid_index()) {
        *error_code = TabletServerErrorPB::CAS_FAILED;
        return Status::IllegalState(Substitute("Request specified cas_config_opid_index "
                                               "of $0 but the committed config has opid_index "
                                               "of $1",
                                               req.cas_config_opid_index(),
                                               committed_config.opid_index()));
      }
    }

    RaftConfigPB new_config = committed_config;
    new_config.clear_opid_index();
    const string& server_uuid = server.permanent_uuid();
    switch (type) {
      case ADD_SERVER:
        // Ensure the server we are adding is not already a member of the configuration.
        if (IsRaftConfigMember(server_uuid, committed_config)) {
          return Status::InvalidArgument(
              Substitute("Server with UUID $0 is already a member of the config. RaftConfig: $1",
                        server_uuid, SecureShortDebugString(committed_config)));
        }
        if (!server.has_member_type()) {
          return Status::InvalidArgument("server must have member_type specified",
                                         SecureShortDebugString(req));
        }
        if (!server.has_last_known_addr()) {
          return Status::InvalidArgument("server must have last_known_addr specified",
                                         SecureShortDebugString(req));
        }
        *new_config.add_peers() = server;
        break;

      case REMOVE_SERVER:
        if (server_uuid == peer_uuid()) {
          return Status::InvalidArgument(
              Substitute("Cannot remove peer $0 from the config because it is the leader. "
                         "Force another leader to be elected to remove this server. "
                         "Active consensus state: $1",
                         server_uuid,
                         SecureShortDebugString(state_->ConsensusStateUnlocked(
                             CONSENSUS_CONFIG_ACTIVE))));
        }
        if (!RemoveFromRaftConfig(&new_config, server_uuid)) {
          return Status::NotFound(
              Substitute("Server with UUID $0 not a member of the config. RaftConfig: $1",
                        server_uuid, SecureShortDebugString(committed_config)));
        }
        break;

      // TODO: Support role change.
      case CHANGE_ROLE:
      default:
        return Status::NotSupported("Role change is not yet implemented.");
    }

    RETURN_NOT_OK(ReplicateConfigChangeUnlocked(committed_config, new_config,
                                                Bind(&RaftConsensus::MarkDirtyOnSuccess,
                                                     Unretained(this),
                                                     string("Config change replication complete"),
                                                     client_cb)));
  }
  peer_manager_->SignalRequest();
  return Status::OK();
}

Status RaftConsensus::UnsafeChangeConfig(const UnsafeChangeConfigRequestPB& req,
                                         TabletServerErrorPB::Code* error_code) {
  if (PREDICT_FALSE(!req.has_new_config())) {
    *error_code = TabletServerErrorPB::INVALID_CONFIG;
    return Status::InvalidArgument("Request must contain 'new_config' argument "
                                   "to UnsafeChangeConfig()", SecureShortDebugString(req));
  }
  if (PREDICT_FALSE(!req.has_caller_id())) {
    *error_code = TabletServerErrorPB::INVALID_CONFIG;
    return Status::InvalidArgument("Must specify 'caller_id' argument to UnsafeChangeConfig()",
                                   SecureShortDebugString(req));
  }

  // Grab the committed config and current term on this node.
  int64_t current_term;
  RaftConfigPB committed_config;
  int64_t all_replicated_index;
  int64 last_committed_index;
  OpId preceding_opid;
  uint64 msg_timestamp;
  string local_peer_uuid;
  {
    // Take the snapshot of the replica state and queue state so that
    // we can stick them in the consensus update request later.
    ReplicaState::UniqueLock lock;
    RETURN_NOT_OK(state_->LockForRead(&lock));
    local_peer_uuid = state_->GetPeerUuid();
    current_term = state_->GetCurrentTermUnlocked();
    committed_config = state_->GetCommittedConfigUnlocked();
    if (state_->IsConfigChangePendingUnlocked()) {
      LOG_WITH_PREFIX_UNLOCKED(WARNING)
            << "Replica has a pending config, but the new config "
            << "will be unsafely changed anyway. "
            << "Currently pending config on the node: "
            << SecureShortDebugString(state_->GetPendingConfigUnlocked());
    }
    all_replicated_index = queue_->GetAllReplicatedIndex();
    last_committed_index = queue_->GetCommittedIndex();
    preceding_opid = queue_->GetLastOpIdInLog();
    msg_timestamp = time_manager_->GetSerialTimestamp().value();
  }

  // Validate that passed replica uuids are part of the committed config
  // on this node.  This allows a manual recovery tool to only have to specify
  // the uuid of each replica in the new config without having to know the
  // addresses of each server (since we can get the address information from
  // the committed config). Additionally, only a subset of the committed config
  // is required for typical cluster repair scenarios.
  unordered_set<string> retained_peer_uuids;
  const RaftConfigPB& config = req.new_config();
  for (const RaftPeerPB& new_peer : config.peers()) {
    const string& peer_uuid = new_peer.permanent_uuid();
    retained_peer_uuids.insert(peer_uuid);
    if (!IsRaftConfigMember(peer_uuid, committed_config)) {
      *error_code = TabletServerErrorPB::INVALID_CONFIG;
      return Status::InvalidArgument(Substitute("Peer with uuid $0 is not in the committed  "
                                                "config on this replica, rejecting the  "
                                                "unsafe config change request for tablet $1. "
                                                "Committed config: $2",
                                                peer_uuid, req.tablet_id(),
                                                SecureShortDebugString(committed_config)));
    }
  }

  RaftConfigPB new_config = committed_config;
  for (const auto& peer : committed_config.peers()) {
    const string& peer_uuid = peer.permanent_uuid();
    if (!ContainsKey(retained_peer_uuids, peer_uuid)) {
      CHECK(RemoveFromRaftConfig(&new_config, peer_uuid));
    }
  }
  // Check that local peer is part of the new config and is a VOTER.
  // Although it is valid for a local replica to not have itself
  // in the committed config, it is rare and a replica without itself
  // in the latest config is definitely not caught up with the latest leader's log.
  if (!IsRaftConfigVoter(local_peer_uuid, new_config)) {
    return Status::InvalidArgument(Substitute("Local replica uuid $0 is not "
                                              "a VOTER in the new config, "
                                              "rejecting the unsafe config "
                                              "change request for tablet $1. "
                                              "Rejected config: $2" ,
                                              local_peer_uuid, req.tablet_id(),
                                              SecureShortDebugString(new_config)));
  }
  new_config.set_unsafe_config_change(true);
  int64 replicate_opid_index = preceding_opid.index() + 1;
  new_config.set_opid_index(replicate_opid_index);

  // Sanity check the new config. 'type' is irrelevant here.
  Status s = VerifyRaftConfig(new_config, UNCOMMITTED_QUORUM);
  if (!s.ok()) {
    *error_code = TabletServerErrorPB::INVALID_CONFIG;
    return Status::InvalidArgument(Substitute("The resulting new config for tablet $0  "
                                              "from passed parameters has failed raft "
                                              "config sanity check: $1",
                                              req.tablet_id(), s.ToString()));
  }

  // Prepare the consensus request as if the request is being generated
  // from a different leader.
  ConsensusRequestPB consensus_req;
  ConsensusResponsePB consensus_resp;
  consensus_req.set_caller_uuid(req.caller_id());
  // Bumping up the term for the consensus request being generated.
  // This makes this request appear to come from a new leader that
  // the local replica doesn't know about yet. If the local replica
  // happens to be the leader, this will cause it to step down.
  int64 new_term = current_term + 1;
  consensus_req.set_caller_term(new_term);
  consensus_req.mutable_preceding_id()->CopyFrom(preceding_opid);
  consensus_req.set_committed_index(last_committed_index);
  consensus_req.set_all_replicated_index(all_replicated_index);

  // Prepare the replicate msg to be replicated.
  ReplicateMsg* replicate = consensus_req.add_ops();
  ChangeConfigRecordPB* cc_req = replicate->mutable_change_config_record();
  cc_req->set_tablet_id(req.tablet_id());
  *cc_req->mutable_old_config() = committed_config;
  *cc_req->mutable_new_config() = new_config;
  OpId* id = replicate->mutable_id();
  // Bumping up both the term and the opid_index from what's found in the log.
  id->set_term(new_term);
  id->set_index(replicate_opid_index);
  replicate->set_op_type(CHANGE_CONFIG_OP);
  replicate->set_timestamp(msg_timestamp);

  VLOG_WITH_PREFIX(3) << "UnsafeChangeConfig: Generated consensus request: "
                      << SecureShortDebugString(consensus_req);

  LOG_WITH_PREFIX(WARNING)
        << "PROCEEDING WITH UNSAFE CONFIG CHANGE ON THIS SERVER, "
        << "COMMITTED CONFIG: " << SecureShortDebugString(committed_config)
        << "NEW CONFIG: " << SecureShortDebugString(new_config);

  s = Update(&consensus_req, &consensus_resp);
  if (!s.ok() || consensus_resp.has_error()) {
    *error_code = TabletServerErrorPB::UNKNOWN_ERROR;
  }
  if (s.ok() && consensus_resp.has_error()) {
    s = StatusFromPB(consensus_resp.error().status());
  }
  return s;
}

void RaftConsensus::Shutdown() {
  // Avoid taking locks if already shut down so we don't violate
  // ThreadRestrictions assertions in the case where the RaftConsensus
  // destructor runs on the reactor thread due to an election callback being
  // the last outstanding reference.
  if (shutdown_.Load(kMemOrderAcquire)) return;

  {
    ReplicaState::UniqueLock lock;
    // Transition to kShuttingDown state.
    CHECK_OK(state_->LockForShutdown(&lock));
    LOG_WITH_PREFIX_UNLOCKED(INFO) << "Raft consensus shutting down.";
  }

  // Close the peer manager.
  peer_manager_->Close();

  // We must close the queue after we close the peers.
  queue_->Close();


  {
    ReplicaState::UniqueLock lock;
    CHECK_OK(state_->LockForShutdown(&lock));
    CHECK_EQ(ReplicaState::kShuttingDown, state_->state());
    CHECK_OK(pending_.CancelPendingTransactions());
    CHECK_OK(state_->ShutdownUnlocked());
    LOG_WITH_PREFIX_UNLOCKED(INFO) << "Raft consensus is shut down!";
  }

  // Shut down things that might acquire locks during destruction.
  thread_pool_->Shutdown();
  failure_monitor_.Shutdown();

  shutdown_.Store(true, kMemOrderRelease);
}

OpId RaftConsensus::GetLatestOpIdFromLog() {
  OpId id;
  log_->GetLatestEntryOpId(&id);
  return id;
}

Status RaftConsensus::StartConsensusOnlyRoundUnlocked(const ReplicateRefPtr& msg) {
  OperationType op_type = msg->get()->op_type();
  CHECK(IsConsensusOnlyOperation(op_type))
      << "Expected a consensus-only op type, got " << OperationType_Name(op_type)
      << ": " << SecureShortDebugString(*msg->get());
  VLOG_WITH_PREFIX_UNLOCKED(1) << "Starting consensus round: "
                               << SecureShortDebugString(msg->get()->id());
  scoped_refptr<ConsensusRound> round(new ConsensusRound(this, msg));
  round->SetConsensusReplicatedCallback(Bind(&RaftConsensus::NonTxRoundReplicationFinished,
                                             Unretained(this),
                                             Unretained(round.get()),
                                             Bind(&RaftConsensus::MarkDirtyOnSuccess,
                                                  Unretained(this),
                                                  string("Replicated consensus-only round"),
                                                  Bind(&DoNothingStatusCB))));
  return AddPendingOperationUnlocked(round);
}

Status RaftConsensus::AdvanceTermForTests(int64_t new_term) {
  ReplicaState::UniqueLock lock;
  CHECK_OK(state_->LockForConfigChange(&lock));
  return HandleTermAdvanceUnlocked(new_term);
}

std::string RaftConsensus::GetRequestVoteLogPrefixUnlocked(const VoteRequestPB& request) const {
  return Substitute("$0Leader $1election vote request",
                    state_->LogPrefixUnlocked(),
                    request.is_pre_election() ? "pre-" : "");
}

void RaftConsensus::FillVoteResponseVoteGranted(VoteResponsePB* response) {
  response->set_responder_term(state_->GetCurrentTermUnlocked());
  response->set_vote_granted(true);
}

void RaftConsensus::FillVoteResponseVoteDenied(ConsensusErrorPB::Code error_code,
                                               VoteResponsePB* response) {
  response->set_responder_term(state_->GetCurrentTermUnlocked());
  response->set_vote_granted(false);
  response->mutable_consensus_error()->set_code(error_code);
}

Status RaftConsensus::RequestVoteRespondInvalidTerm(const VoteRequestPB* request,
                                                    VoteResponsePB* response) {
  FillVoteResponseVoteDenied(ConsensusErrorPB::INVALID_TERM, response);
  string msg = Substitute("$0: Denying vote to candidate $1 for earlier term $2. "
                          "Current term is $3.",
                          GetRequestVoteLogPrefixUnlocked(*request),
                          request->candidate_uuid(),
                          request->candidate_term(),
                          state_->GetCurrentTermUnlocked());
  LOG(INFO) << msg;
  StatusToPB(Status::InvalidArgument(msg), response->mutable_consensus_error()->mutable_status());
  return Status::OK();
}

Status RaftConsensus::RequestVoteRespondVoteAlreadyGranted(const VoteRequestPB* request,
                                                           VoteResponsePB* response) {
  FillVoteResponseVoteGranted(response);
  LOG(INFO) << Substitute("$0: Already granted yes vote for candidate $1 in term $2. "
                          "Re-sending same reply.",
                          GetRequestVoteLogPrefixUnlocked(*request),
                          request->candidate_uuid(),
                          request->candidate_term());
  return Status::OK();
}

Status RaftConsensus::RequestVoteRespondAlreadyVotedForOther(const VoteRequestPB* request,
                                                             VoteResponsePB* response) {
  FillVoteResponseVoteDenied(ConsensusErrorPB::ALREADY_VOTED, response);
  string msg = Substitute("$0: Denying vote to candidate $1 in current term $2: "
                          "Already voted for candidate $3 in this term.",
                          GetRequestVoteLogPrefixUnlocked(*request),
                          request->candidate_uuid(),
                          state_->GetCurrentTermUnlocked(),
                          state_->GetVotedForCurrentTermUnlocked());
  LOG(INFO) << msg;
  StatusToPB(Status::InvalidArgument(msg), response->mutable_consensus_error()->mutable_status());
  return Status::OK();
}

Status RaftConsensus::RequestVoteRespondLastOpIdTooOld(const OpId& local_last_logged_opid,
                                                       const VoteRequestPB* request,
                                                       VoteResponsePB* response) {
  FillVoteResponseVoteDenied(ConsensusErrorPB::LAST_OPID_TOO_OLD, response);
  string msg = Substitute("$0: Denying vote to candidate $1 for term $2 because "
                          "replica has last-logged OpId of $3, which is greater than that of the "
                          "candidate, which has last-logged OpId of $4.",
                          GetRequestVoteLogPrefixUnlocked(*request),
                          request->candidate_uuid(),
                          request->candidate_term(),
                          SecureShortDebugString(local_last_logged_opid),
                          SecureShortDebugString(request->candidate_status().last_received()));
  LOG(INFO) << msg;
  StatusToPB(Status::InvalidArgument(msg), response->mutable_consensus_error()->mutable_status());
  return Status::OK();
}

Status RaftConsensus::RequestVoteRespondLeaderIsAlive(const VoteRequestPB* request,
                                                      VoteResponsePB* response) {
  FillVoteResponseVoteDenied(ConsensusErrorPB::LEADER_IS_ALIVE, response);
  string msg = Substitute("$0: Denying vote to candidate $1 for term $2 because "
                          "replica is either leader or believes a valid leader to "
                          "be alive.",
                          GetRequestVoteLogPrefixUnlocked(*request),
                          request->candidate_uuid(),
                          request->candidate_term());
  LOG(INFO) << msg;
  StatusToPB(Status::InvalidArgument(msg), response->mutable_consensus_error()->mutable_status());
  return Status::OK();
}

Status RaftConsensus::RequestVoteRespondIsBusy(const VoteRequestPB* request,
                                               VoteResponsePB* response) {
  FillVoteResponseVoteDenied(ConsensusErrorPB::CONSENSUS_BUSY, response);
  string msg = Substitute("$0: Denying vote to candidate $1 for term $2 because "
                          "replica is already servicing an update from a current leader "
                          "or another vote.",
                          GetRequestVoteLogPrefixUnlocked(*request),
                          request->candidate_uuid(),
                          request->candidate_term());
  LOG(INFO) << msg;
  StatusToPB(Status::ServiceUnavailable(msg),
             response->mutable_consensus_error()->mutable_status());
  return Status::OK();
}

Status RaftConsensus::RequestVoteRespondVoteGranted(const VoteRequestPB* request,
                                                    VoteResponsePB* response) {
  // We know our vote will be "yes", so avoid triggering an election while we
  // persist our vote to disk. We use an exponential backoff to avoid too much
  // split-vote contention when nodes display high latencies.
  MonoDelta additional_backoff = LeaderElectionExpBackoffDeltaUnlocked();
  RETURN_NOT_OK(SnoozeFailureDetectorUnlocked(additional_backoff, ALLOW_LOGGING));

  if (!request->is_pre_election()) {
    // Persist our vote to disk.
    RETURN_NOT_OK(state_->SetVotedForCurrentTermUnlocked(request->candidate_uuid()));
  }

  FillVoteResponseVoteGranted(response);

  // Give peer time to become leader. Snooze one more time after persisting our
  // vote. When disk latency is high, this should help reduce churn.
  RETURN_NOT_OK(SnoozeFailureDetectorUnlocked(additional_backoff, DO_NOT_LOG));

  LOG(INFO) << Substitute("$0: Granting yes vote for candidate $1 in term $2.",
                          GetRequestVoteLogPrefixUnlocked(*request),
                          request->candidate_uuid(),
                          state_->GetCurrentTermUnlocked());
  return Status::OK();
}

RaftPeerPB::Role RaftConsensus::role() const {
  ReplicaState::UniqueLock lock;
  CHECK_OK(state_->LockForRead(&lock));
  return state_->GetActiveRoleUnlocked();
}

std::string RaftConsensus::LogPrefixUnlocked() {
  return state_->LogPrefixUnlocked();
}

std::string RaftConsensus::LogPrefix() {
  return state_->LogPrefix();
}

void RaftConsensus::SetLeaderUuidUnlocked(const string& uuid) {
  failed_elections_since_stable_leader_ = 0;
  state_->SetLeaderUuidUnlocked(uuid);
  MarkDirty("New leader " + uuid);
}


Status RaftConsensus::ReplicateConfigChangeUnlocked(const RaftConfigPB& old_config,
                                                    const RaftConfigPB& new_config,
                                                    const StatusCallback& client_cb) {
  auto cc_replicate = new ReplicateMsg();
  cc_replicate->set_op_type(CHANGE_CONFIG_OP);
  ChangeConfigRecordPB* cc_req = cc_replicate->mutable_change_config_record();
  cc_req->set_tablet_id(tablet_id());
  *cc_req->mutable_old_config() = old_config;
  *cc_req->mutable_new_config() = new_config;
  CHECK_OK(time_manager_->AssignTimestamp(cc_replicate));

  scoped_refptr<ConsensusRound> round(
      new ConsensusRound(this, make_scoped_refptr(new RefCountedReplicate(cc_replicate))));
  round->SetConsensusReplicatedCallback(Bind(&RaftConsensus::NonTxRoundReplicationFinished,
                                             Unretained(this),
                                             Unretained(round.get()),
                                             client_cb));

  CHECK_OK(AppendNewRoundToQueueUnlocked(round));
  return Status::OK();
}

Status RaftConsensus::RefreshConsensusQueueAndPeersUnlocked() {
  DCHECK_EQ(RaftPeerPB::LEADER, state_->GetActiveRoleUnlocked());
  const RaftConfigPB& active_config = state_->GetActiveConfigUnlocked();

  // Change the peers so that we're able to replicate messages remotely and
  // locally. The peer manager must be closed before updating the active config
  // in the queue -- when the queue is in LEADER mode, it checks that all
  // registered peers are a part of the active config.
  peer_manager_->Close();
  // TODO(todd): should use queue committed index here? in that case do
  // we need to pass it in at all?
  queue_->SetLeaderMode(pending_.GetCommittedIndex(),
                        state_->GetCurrentTermUnlocked(),
                        active_config);
  RETURN_NOT_OK(peer_manager_->UpdateRaftConfig(active_config));
  return Status::OK();
}

string RaftConsensus::peer_uuid() const {
  return state_->GetPeerUuid();
}

string RaftConsensus::tablet_id() const {
  return state_->GetOptions().tablet_id;
}

ConsensusStatePB RaftConsensus::ConsensusState(ConsensusConfigType type) const {
  ReplicaState::UniqueLock lock;
  CHECK_OK(state_->LockForRead(&lock));
  return state_->ConsensusStateUnlocked(type);
}

RaftConfigPB RaftConsensus::CommittedConfig() const {
  ReplicaState::UniqueLock lock;
  CHECK_OK(state_->LockForRead(&lock));
  return state_->GetCommittedConfigUnlocked();
}

void RaftConsensus::DumpStatusHtml(std::ostream& out) const {
  out << "<h1>Raft Consensus State</h1>" << std::endl;

  out << "<h2>State</h2>" << std::endl;
  out << "<pre>" << EscapeForHtmlToString(state_->ToString()) << "</pre>" << std::endl;
  out << "<h2>Queue</h2>" << std::endl;
  out << "<pre>" << EscapeForHtmlToString(queue_->ToString()) << "</pre>" << std::endl;

  // Dump the queues on a leader.
  RaftPeerPB::Role role;
  {
    ReplicaState::UniqueLock lock;
    CHECK_OK(state_->LockForRead(&lock));
    role = state_->GetActiveRoleUnlocked();
  }
  if (role == RaftPeerPB::LEADER) {
    out << "<h2>Queue overview</h2>" << std::endl;
    out << "<pre>" << EscapeForHtmlToString(queue_->ToString()) << "</pre>" << std::endl;
    out << "<hr/>" << std::endl;
    out << "<h2>Queue details</h2>" << std::endl;
    queue_->DumpToHtml(out);
  }
}

ReplicaState* RaftConsensus::GetReplicaStateForTests() {
  return state_.get();
}

void RaftConsensus::ElectionCallback(ElectionReason reason, const ElectionResult& result) {
  // The election callback runs on a reactor thread, so we need to defer to our
  // threadpool. If the threadpool is already shut down for some reason, it's OK --
  // we're OK with the callback never running.
  WARN_NOT_OK(thread_pool_->SubmitClosure(Bind(&RaftConsensus::DoElectionCallback,
                                               this, reason, result)),
              state_->LogPrefixThreadSafe() + "Unable to run election callback");
}

void RaftConsensus::DoElectionCallback(ElectionReason reason, const ElectionResult& result) {
  const int64_t election_term = result.vote_request.candidate_term();
  const bool was_pre_election = result.vote_request.is_pre_election();
  const char* election_type = was_pre_election ? "pre-election" : "election";

  // Snooze to avoid the election timer firing again as much as possible.
  {
    ReplicaState::UniqueLock lock;
    CHECK_OK(state_->LockForRead(&lock));
    // We need to snooze when we win and when we lose:
    // - When we win because we're about to disable the timer and become leader.
    // - When we lose or otherwise we can fall into a cycle, where everyone keeps
    //   triggering elections but no election ever completes because by the time they
    //   finish another one is triggered already.
    // We ignore the status as we don't want to fail if we the timer is
    // disabled.
    ignore_result(SnoozeFailureDetectorUnlocked(LeaderElectionExpBackoffDeltaUnlocked(),
                                                ALLOW_LOGGING));

    if (result.decision == VOTE_DENIED) {
      failed_elections_since_stable_leader_++;

      // If we called an election and one of the voters had a higher term than we did,
      // we should bump our term before we potentially try again. This is particularly
      // important with pre-elections to avoid getting "stuck" in a case like:
      //    Peer A: has ops through 1.10, term = 2, voted in term 2 for peer C
      //    Peer B: has ops through 1.15, term = 1
      // In this case, Peer B will reject peer A's pre-elections for term 3 because
      // the local log is longer. Peer A will reject B's pre-elections for term 2
      // because it already voted in term 2. The check below ensures that peer B
      // will bump to term 2 when it gets the vote rejection, such that its
      // next pre-election (for term 3) would succeed.
      if (result.highest_voter_term > state_->GetCurrentTermUnlocked()) {
        HandleTermAdvanceUnlocked(result.highest_voter_term);
      }

      LOG_WITH_PREFIX_UNLOCKED(INFO)
          << "Leader " << election_type << " lost for term " << election_term
          << ". Reason: "
          << (!result.message.empty() ? result.message : "None given");
      return;
    }
  }

  // The vote was granted, become leader.
  ReplicaState::UniqueLock lock;
  Status s = state_->LockForConfigChange(&lock);
  if (PREDICT_FALSE(!s.ok())) {
    LOG_WITH_PREFIX(INFO) << "Received " << election_type << " callback for term "
                          << election_term << " while not running: "
                          << s.ToString();
    return;
  }

  // In a pre-election, we collected votes for the _next_ term.
  // So, we need to adjust our expectations of what the current term should be.
  int64_t election_started_in_term = election_term;
  if (was_pre_election) {
    election_started_in_term--;
  }

  if (election_started_in_term != state_->GetCurrentTermUnlocked()) {
    LOG_WITH_PREFIX_UNLOCKED(INFO)
        << "Leader " << election_type << " decision vote started in "
        << "defunct term " << election_started_in_term << ": "
        << (result.decision == VOTE_GRANTED ? "won" : "lost");
    return;
  }

  const RaftConfigPB& active_config = state_->GetActiveConfigUnlocked();
  if (!IsRaftConfigVoter(state_->GetPeerUuid(), active_config)) {
    LOG_WITH_PREFIX_UNLOCKED(WARNING) << "Leader " << election_type
                                      << " decision while not in active config. "
                                      << "Result: Term " << election_term << ": "
                                      << (result.decision == VOTE_GRANTED ? "won" : "lost")
                                      << ". RaftConfig: " << SecureShortDebugString(active_config);
    return;
  }

  if (state_->GetActiveRoleUnlocked() == RaftPeerPB::LEADER) {
    // If this was a pre-election, it's possible to see the following interleaving:
    //
    //  1. Term N (follower): send a real election for term N
    //  2. Election callback expires again
    //  3. Term N (follower): send a pre-election for term N+1
    //  4. Election callback for real election from term N completes.
    //     Peer is now leader for term N.
    //  5. Pre-election callback from term N+1 completes, even though
    //     we are currently a leader of term N.
    // In this case, we should just ignore the pre-election, since we're
    // happily the leader of the prior term.
    if (was_pre_election) return;
    LOG_WITH_PREFIX_UNLOCKED(DFATAL)
        << "Leader " << election_type << " callback while already leader! "
        << "Result: Term " << election_term << ": "
        << (result.decision == VOTE_GRANTED ? "won" : "lost");
    return;
  }

  LOG_WITH_PREFIX_UNLOCKED(INFO) << "Leader " << election_type << " won for term " << election_term;

  if (was_pre_election) {
    // We just won the pre-election. So, we need to call a real election.
    lock.unlock();
    WARN_NOT_OK(StartElection(NORMAL_ELECTION, reason),
                "Couldn't start leader election after successful pre-election");
  } else {
    // We won a real election. Convert role to LEADER.
    SetLeaderUuidUnlocked(state_->GetPeerUuid());

    // TODO(todd): BecomeLeaderUnlocked() can fail due to state checks during shutdown.
    // It races with the above state check.
    // This could be a problem during tablet deletion.
    CHECK_OK(BecomeLeaderUnlocked());
  }
}

Status RaftConsensus::GetLastOpId(OpIdType type, OpId* id) {
  ReplicaState::UniqueLock lock;
  RETURN_NOT_OK(state_->LockForRead(&lock));
  if (type == RECEIVED_OPID) {
    *DCHECK_NOTNULL(id) = queue_->GetLastOpIdInLog();
  } else if (type == COMMITTED_OPID) {
    id->set_term(pending_.GetTermWithLastCommittedOp());
    id->set_index(pending_.GetCommittedIndex());
  } else {
    return Status::InvalidArgument("Unsupported OpIdType", OpIdType_Name(type));
  }
  return Status::OK();
}

log::RetentionIndexes RaftConsensus::GetRetentionIndexes() {
  // Grab the watermarks from the queue. It's OK to fetch these two watermarks
  // separately -- the worst case is we see a relatively "out of date" watermark
  // which just means we'll retain slightly more than necessary in this invocation
  // of log GC.
  return log::RetentionIndexes(queue_->GetCommittedIndex(), // for durability
                               queue_->GetAllReplicatedIndex()); // for peers
}

void RaftConsensus::MarkDirty(const std::string& reason) {
  WARN_NOT_OK(thread_pool_->SubmitClosure(Bind(mark_dirty_clbk_, reason)),
              state_->LogPrefixThreadSafe() + "Unable to run MarkDirty callback");
}

void RaftConsensus::MarkDirtyOnSuccess(const string& reason,
                                       const StatusCallback& client_cb,
                                       const Status& status) {
  if (PREDICT_TRUE(status.ok())) {
    MarkDirty(reason);
  }
  client_cb.Run(status);
}

void RaftConsensus::NonTxRoundReplicationFinished(ConsensusRound* round,
                                                  const StatusCallback& client_cb,
                                                  const Status& status) {
  // NOTE: the ReplicaState lock is held here because this is triggered by
  // ReplicaState's abort or commit paths.
  OperationType op_type = round->replicate_msg()->op_type();
  const string& op_type_str = OperationType_Name(op_type);
  CHECK(IsConsensusOnlyOperation(op_type)) << "Unexpected op type: " << op_type_str;

  if (op_type == CHANGE_CONFIG_OP) {
    CompleteConfigChangeRoundUnlocked(round, status);
    // Fall through to the generic handling.
  }

  if (!status.ok()) {
    LOG(INFO) << state_->LogPrefixThreadSafe() << op_type_str << " replication failed: "
              << status.ToString();
    client_cb.Run(status);
    return;
  }
  VLOG(1) << state_->LogPrefixThreadSafe() << "Committing " << op_type_str << " with op id "
          << round->id();
  gscoped_ptr<CommitMsg> commit_msg(new CommitMsg);
  commit_msg->set_op_type(round->replicate_msg()->op_type());
  *commit_msg->mutable_commited_op_id() = round->id();

  CHECK_OK(log_->AsyncAppendCommit(std::move(commit_msg),
                                   Bind(CrashIfNotOkStatusCB,
                                        "Enqueued commit operation failed to write to WAL")));

  client_cb.Run(status);
}

void RaftConsensus::CompleteConfigChangeRoundUnlocked(ConsensusRound* round, const Status& status) {
  const OpId& op_id = round->replicate_msg()->id();

  if (!status.ok()) {
    // If the config change being aborted is the current pending one, abort it.
    if (state_->IsConfigChangePendingUnlocked() &&
        state_->GetPendingConfigUnlocked().opid_index() == op_id.index()) {
      LOG_WITH_PREFIX_UNLOCKED(INFO) << "Aborting config change with OpId "
                                     << op_id << ": " << status.ToString();
      state_->ClearPendingConfigUnlocked();
    } else {
      LOG_WITH_PREFIX_UNLOCKED(INFO)
          << "Skipping abort of non-pending config change with OpId "
          << op_id << ": " << status.ToString();
    }

    // It's possible to abort a config change which isn't the pending one in the following
    // sequence:
    // - replicate a config change
    // - it gets committed, so we write the new config to disk as the Committed configuration
    // - we crash before the COMMIT message hits the WAL
    // - we restart the server, and the config change is added as a pending round again,
    //   but isn't set as Pending because it's already committed.
    // - we delete the tablet before committing it
    // See KUDU-1735.
    return;
  }

  // Commit the successful config change.

  DCHECK(round->replicate_msg()->change_config_record().has_old_config());
  DCHECK(round->replicate_msg()->change_config_record().has_new_config());
  RaftConfigPB old_config = round->replicate_msg()->change_config_record().old_config();
  RaftConfigPB new_config = round->replicate_msg()->change_config_record().new_config();
  DCHECK(old_config.has_opid_index());
  DCHECK(new_config.has_opid_index());
  // Check if the pending Raft config has an OpId less than the committed
  // config. If so, this is a replay at startup in which the COMMIT
  // messages were delayed.
  const RaftConfigPB& committed_config = state_->GetCommittedConfigUnlocked();
  if (new_config.opid_index() > committed_config.opid_index()) {
    LOG_WITH_PREFIX_UNLOCKED(INFO)
        << "Committing config change with OpId "
        << op_id << ": "
        << DiffRaftConfigs(old_config, new_config)
        << ". New config: { " << SecureShortDebugString(new_config) << " }";
    CHECK_OK(state_->SetCommittedConfigUnlocked(new_config));
  } else {
    LOG_WITH_PREFIX_UNLOCKED(INFO)
        << "Ignoring commit of config change with OpId "
        << op_id << " because the committed config has OpId index "
        << committed_config.opid_index() << ". The config change we are ignoring is: "
        << "Old config: { " << SecureShortDebugString(old_config) << " }. "
        << "New config: { " << SecureShortDebugString(new_config) << " }";
  }
}


Status RaftConsensus::EnsureFailureDetectorEnabledUnlocked() {
  if (PREDICT_FALSE(!FLAGS_enable_leader_failure_detection)) {
    return Status::OK();
  }
  if (failure_detector_->IsTracking(kTimerId)) {
    return Status::OK();
  }
  return failure_detector_->Track(kTimerId,
                                  MonoTime::Now(),
                                  // Unretained to avoid a circular ref.
                                  Bind(&RaftConsensus::ReportFailureDetected, Unretained(this)));
}

Status RaftConsensus::EnsureFailureDetectorDisabledUnlocked() {
  if (PREDICT_FALSE(!FLAGS_enable_leader_failure_detection)) {
    return Status::OK();
  }

  if (!failure_detector_->IsTracking(kTimerId)) {
    return Status::OK();
  }
  return failure_detector_->UnTrack(kTimerId);
}

Status RaftConsensus::ExpireFailureDetectorUnlocked() {
  if (PREDICT_FALSE(!FLAGS_enable_leader_failure_detection)) {
    return Status::OK();
  }

  return failure_detector_->MessageFrom(kTimerId, MonoTime::Min());
}

Status RaftConsensus::SnoozeFailureDetectorUnlocked() {
  return SnoozeFailureDetectorUnlocked(MonoDelta::FromMicroseconds(0), DO_NOT_LOG);
}

Status RaftConsensus::SnoozeFailureDetectorUnlocked(const MonoDelta& additional_delta,
                                                    AllowLogging allow_logging) {
  if (PREDICT_FALSE(!FLAGS_enable_leader_failure_detection)) {
    return Status::OK();
  }

  MonoTime time = MonoTime::Now() + additional_delta;

  if (allow_logging == ALLOW_LOGGING) {
    LOG_WITH_PREFIX_UNLOCKED(INFO) << "Snoozing failure detection for election timeout "
                                   << "plus an additional " + additional_delta.ToString();
  }

  return failure_detector_->MessageFrom(kTimerId, time);
}

MonoDelta RaftConsensus::MinimumElectionTimeout() const {
  int32_t failure_timeout = FLAGS_leader_failure_max_missed_heartbeat_periods *
      FLAGS_raft_heartbeat_interval_ms;
  return MonoDelta::FromMilliseconds(failure_timeout);
}

MonoDelta RaftConsensus::LeaderElectionExpBackoffDeltaUnlocked() {
  // Compute a backoff factor based on how many leader elections have
  // failed since a stable leader was last seen.
  double backoff_factor = pow(1.5, failed_elections_since_stable_leader_ + 1);
  double min_timeout = MinimumElectionTimeout().ToMilliseconds();
  double max_timeout = std::min<double>(
      min_timeout * backoff_factor,
      FLAGS_leader_failure_exp_backoff_max_delta_ms);

  // Randomize the timeout between the minimum and the calculated value.
  // We do this after the above capping to the max. Otherwise, after a
  // churny period, we'd end up highly likely to backoff exactly the max
  // amount.
  double timeout = min_timeout + (max_timeout - min_timeout) * rng_.NextDoubleFraction();
  DCHECK_GE(timeout, min_timeout);

  return MonoDelta::FromMilliseconds(timeout);
}

Status RaftConsensus::HandleTermAdvanceUnlocked(ConsensusTerm new_term,
                                                ReplicaState::FlushToDisk flush) {
  if (new_term <= state_->GetCurrentTermUnlocked()) {
    return Status::IllegalState(Substitute("Can't advance term to: $0 current term: $1 is higher.",
                                           new_term, state_->GetCurrentTermUnlocked()));
  }
  if (state_->GetActiveRoleUnlocked() == RaftPeerPB::LEADER) {
    LOG_WITH_PREFIX_UNLOCKED(INFO) << "Stepping down as leader of term "
                                   << state_->GetCurrentTermUnlocked();
    RETURN_NOT_OK(BecomeReplicaUnlocked());
  }

  LOG_WITH_PREFIX_UNLOCKED(INFO) << "Advancing to term " << new_term;
  RETURN_NOT_OK(state_->SetCurrentTermUnlocked(new_term, flush));
  term_metric_->set_value(new_term);
  last_received_cur_leader_ = MinimumOpId();
  return Status::OK();
}

}  // namespace consensus
}  // namespace kudu
