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
#ifndef KUDU_INTEGRATION_TESTS_ITEST_UTIL_H_
#define KUDU_INTEGRATION_TESTS_ITEST_UTIL_H_

#include <glog/stl_logging.h>
#include <string>
#include <utility>
#include <vector>

#include "kudu/client/client-test-util.h"
#include "kudu/client/schema-internal.h"
#include "kudu/consensus/quorum_util.h"
#include "kudu/gutil/strings/split.h"
#include "kudu/integration-tests/cluster_itest_util.h"
#include "kudu/integration-tests/cluster_verifier.h"
#include "kudu/integration-tests/external_mini_cluster.h"
#include "kudu/integration-tests/external_mini_cluster_fs_inspector.h"
#include "kudu/master/master.proxy.h"
#include "kudu/tserver/tablet_server-test-base.h"
#include "kudu/util/pb_util.h"
#include "kudu/util/random.h"
#include "kudu/util/test_util.h"

DECLARE_int32(consensus_rpc_timeout_ms);

DEFINE_string(ts_flags, "", "Flags to pass through to tablet servers");
DEFINE_string(master_flags, "", "Flags to pass through to masters");

DEFINE_int32(num_tablet_servers, 3, "Number of tablet servers to start");
DEFINE_int32(num_replicas, 3, "Number of replicas per tablet server");

#define ASSERT_ALL_REPLICAS_AGREE(count) \
  NO_FATALS(AssertAllReplicasAgree(count))

namespace kudu {
namespace tserver {

using client::KuduSchemaFromSchema;
using consensus::OpId;
using consensus::RaftPeerPB;
using itest::GetReplicaStatusAndCheckIfLeader;
using itest::TabletReplicaMap;
using itest::TabletServerMap;
using itest::TServerDetails;
using master::GetTableLocationsRequestPB;
using master::GetTableLocationsResponsePB;
using master::TabletLocationsPB;
using rpc::RpcController;

static const int kMaxRetries = 20;

// A base for tablet server integration tests.
class TabletServerIntegrationTestBase : public TabletServerTestBase {
 public:

  TabletServerIntegrationTestBase() : random_(SeedRandom()) {}

  void SetUp() OVERRIDE {
    TabletServerTestBase::SetUp();
  }

  void AddExtraFlags(const std::string& flags_str, std::vector<std::string>* flags) {
    if (flags_str.empty()) {
      return;
    }
    std::vector<std::string> split_flags = strings::Split(flags_str, " ");
    for (const std::string& flag : split_flags) {
      flags->push_back(flag);
    }
  }

  void CreateCluster(const std::string& data_root_path,
                     const std::vector<std::string>& non_default_ts_flags,
                     const std::vector<std::string>& non_default_master_flags) {

    LOG(INFO) << "Starting cluster with:";
    LOG(INFO) << "--------------";
    LOG(INFO) << FLAGS_num_tablet_servers << " tablet servers";
    LOG(INFO) << FLAGS_num_replicas << " replicas per TS";
    LOG(INFO) << "--------------";

    ExternalMiniClusterOptions opts;
    opts.num_tablet_servers = FLAGS_num_tablet_servers;
    opts.data_root = GetTestPath(data_root_path);

    // Enable exactly once semantics for tests.

    // If the caller passed no flags use the default ones, where we stress consensus by setting
    // low timeouts and frequent cache misses.
    if (non_default_ts_flags.empty()) {
      opts.extra_tserver_flags.push_back("--log_cache_size_limit_mb=10");
      opts.extra_tserver_flags.push_back(strings::Substitute("--consensus_rpc_timeout_ms=$0",
                                                             FLAGS_consensus_rpc_timeout_ms));
    } else {
      for (const std::string& flag : non_default_ts_flags) {
        opts.extra_tserver_flags.push_back(flag);
      }
    }
    for (const std::string& flag : non_default_master_flags) {
      opts.extra_master_flags.push_back(flag);
    }

    AddExtraFlags(FLAGS_ts_flags, &opts.extra_tserver_flags);
    AddExtraFlags(FLAGS_master_flags, &opts.extra_master_flags);

    cluster_.reset(new ExternalMiniCluster(opts));
    ASSERT_OK(cluster_->Start());
    inspect_.reset(new itest::ExternalMiniClusterFsInspector(cluster_.get()));
    CreateTSProxies();
  }

  // Creates TSServerDetails instance for each TabletServer and stores them
  // in 'tablet_servers_'.
  void CreateTSProxies() {
    CHECK(tablet_servers_.empty());
    CHECK_OK(itest::CreateTabletServerMap(cluster_->master_proxy().get(),
                                          client_messenger_,
                                          &tablet_servers_));
  }

  // Waits that all replicas for a all tablets of 'kTableId' table are online
  // and creates the tablet_replicas_ map.
  void WaitForReplicasAndUpdateLocations() {
    bool replicas_missing = true;
    for (int num_retries = 0; replicas_missing && num_retries < kMaxRetries; num_retries++) {
      std::unordered_multimap<std::string, TServerDetails*> tablet_replicas;
      GetTableLocationsRequestPB req;
      GetTableLocationsResponsePB resp;
      RpcController controller;
      req.mutable_table()->set_table_name(kTableId);
      controller.set_timeout(MonoDelta::FromSeconds(1));
      CHECK_OK(cluster_->master_proxy()->GetTableLocations(req, &resp, &controller));
      CHECK_OK(controller.status());
      if (resp.has_error()) {
        switch (resp.error().code()) {
          case master::MasterErrorPB::TABLET_NOT_RUNNING:
            LOG(WARNING)<< "At least one tablet is not yet running";
            break;

          case master::MasterErrorPB::NOT_THE_LEADER:   // fallthrough
          case master::MasterErrorPB::CATALOG_MANAGER_NOT_INITIALIZED:
            LOG(WARNING)<< "CatalogManager is not yet ready to serve requests";
            break;

          default:
            FAIL() << "Response had a fatal error: "
                   << SecureShortDebugString(resp.error());
            break;  // unreachable
        }
        SleepFor(MonoDelta::FromSeconds(1));
        continue;
      }

      for (const master::TabletLocationsPB& location : resp.tablet_locations()) {
        for (const master::TabletLocationsPB_ReplicaPB& replica : location.replicas()) {
          TServerDetails* server = FindOrDie(tablet_servers_, replica.ts_info().permanent_uuid());
          tablet_replicas.insert(pair<std::string, TServerDetails*>(location.tablet_id(), server));
        }

        if (tablet_replicas.count(location.tablet_id()) < FLAGS_num_replicas) {
          LOG(WARNING)<< "Couldn't find the leader and/or replicas. Location: "
              << SecureShortDebugString(location);
          replicas_missing = true;
          SleepFor(MonoDelta::FromSeconds(1));
          break;
        }

        replicas_missing = false;
      }
      if (!replicas_missing) {
        tablet_replicas_ = tablet_replicas;
      }
    }

    // GetTableLocations() does not guarantee that all replicas are actually
    // running. Some may still be bootstrapping. Wait for them before
    // returning.
    //
    // Just as with the above loop and its behavior once kMaxRetries is
    // reached, the wait here is best effort only. That is, if the wait
    // deadline expires, the resulting timeout failure is ignored.
    for (int i = 0; i < cluster_->num_tablet_servers(); i++) {
      ExternalTabletServer* ts = cluster_->tablet_server(i);
      int expected_tablet_count = 0;
      for (const auto& e : tablet_replicas_) {
        if (ts->uuid() == e.second->uuid()) {
          expected_tablet_count++;
        }
      }
      LOG(INFO) << strings::Substitute(
          "Waiting for $0 tablets on tserver $1 to finish bootstrapping",
          expected_tablet_count, ts->uuid());
      cluster_->WaitForTabletsRunning(ts, expected_tablet_count,
                                      MonoDelta::FromSeconds(20));
    }
  }

  // Returns the last committed leader of the consensus configuration. Tries to get it from master
  // but then actually tries to the get the committed consensus configuration to make sure.
  TServerDetails* GetLeaderReplicaOrNull(const std::string& tablet_id) {
    std::string leader_uuid;
    Status master_found_leader_result = GetTabletLeaderUUIDFromMaster(tablet_id, &leader_uuid);

    // See if the master is up to date. I.e. if it does report a leader and if the
    // replica it reports as leader is still alive and (at least thinks) its still
    // the leader.
    TServerDetails* leader;
    if (master_found_leader_result.ok()) {
      leader = GetReplicaWithUuidOrNull(tablet_id, leader_uuid);
      if (leader && GetReplicaStatusAndCheckIfLeader(leader, tablet_id,
                                                     MonoDelta::FromMilliseconds(100)).ok()) {
        return leader;
      }
    }

    // The replica we got from the master (if any) is either dead or not the leader.
    // Find the actual leader.
    pair<TabletReplicaMap::iterator, TabletReplicaMap::iterator> range =
        tablet_replicas_.equal_range(tablet_id);
    std::vector<TServerDetails*> replicas_copy;
    for (;range.first != range.second; ++range.first) {
      replicas_copy.push_back((*range.first).second);
    }

    std::random_shuffle(replicas_copy.begin(), replicas_copy.end());
    for (TServerDetails* replica : replicas_copy) {
      if (GetReplicaStatusAndCheckIfLeader(replica, tablet_id,
                                           MonoDelta::FromMilliseconds(100)).ok()) {
        return replica;
      }
    }
    return NULL;
  }

  Status GetLeaderReplicaWithRetries(const std::string& tablet_id,
                                     TServerDetails** leader,
                                     int max_attempts = 100) {
    int attempts = 0;
    while (attempts < max_attempts) {
      *leader = GetLeaderReplicaOrNull(tablet_id);
      if (*leader) {
        return Status::OK();
      }
      attempts++;
      SleepFor(MonoDelta::FromMilliseconds(100 * attempts));
    }
    return Status::NotFound("Leader replica not found");
  }

  Status GetTabletLeaderUUIDFromMaster(const std::string& tablet_id, std::string* leader_uuid) {
    GetTableLocationsRequestPB req;
    GetTableLocationsResponsePB resp;
    RpcController controller;
    controller.set_timeout(MonoDelta::FromMilliseconds(100));
    req.mutable_table()->set_table_name(kTableId);

    RETURN_NOT_OK(cluster_->master_proxy()->GetTableLocations(req, &resp, &controller));
    for (const TabletLocationsPB& loc : resp.tablet_locations()) {
      if (loc.tablet_id() == tablet_id) {
        for (const TabletLocationsPB::ReplicaPB& replica : loc.replicas()) {
          if (replica.role() == RaftPeerPB::LEADER) {
            *leader_uuid = replica.ts_info().permanent_uuid();
            return Status::OK();
          }
        }
      }
    }
    return Status::NotFound("Unable to find leader for tablet", tablet_id);
  }

  TServerDetails* GetReplicaWithUuidOrNull(const std::string& tablet_id,
                                           const std::string& uuid) {
    pair<TabletReplicaMap::iterator, TabletReplicaMap::iterator> range =
        tablet_replicas_.equal_range(tablet_id);
    for (;range.first != range.second; ++range.first) {
      if ((*range.first).second->instance_id.permanent_uuid() == uuid) {
        return (*range.first).second;
      }
    }
    return NULL;
  }

  // Gets the the locations of the consensus configuration and waits until all replicas
  // are available for all tablets.
  void WaitForTSAndReplicas() {
    int num_retries = 0;
    // make sure the replicas are up and find the leader
    while (true) {
      if (num_retries >= kMaxRetries) {
        FAIL() << " Reached max. retries while looking up the config.";
      }

      Status status = cluster_->WaitForTabletServerCount(FLAGS_num_tablet_servers,
                                                         MonoDelta::FromSeconds(5));
      if (status.IsTimedOut()) {
        LOG(WARNING)<< "Timeout waiting for all replicas to be online, retrying...";
        num_retries++;
        continue;
      }
      break;
    }
    WaitForReplicasAndUpdateLocations();
  }

  // Removes a set of servers from the replicas_ list.
  // Handy for controlling who to validate against after killing servers.
  void PruneFromReplicas(const unordered_set<std::string>& uuids) {
    auto iter = tablet_replicas_.begin();
    while (iter != tablet_replicas_.end()) {
      if (uuids.count((*iter).second->instance_id.permanent_uuid()) != 0) {
        iter = tablet_replicas_.erase(iter);
        continue;
      }
      ++iter;
    }

    for (const std::string& uuid : uuids) {
      delete EraseKeyReturnValuePtr(&tablet_servers_, uuid);
    }
  }

  void GetOnlyLiveFollowerReplicas(const std::string& tablet_id,
                                   std::vector<TServerDetails*>* followers) {
    followers->clear();
    TServerDetails* leader;
    CHECK_OK(GetLeaderReplicaWithRetries(tablet_id, &leader));

    std::vector<TServerDetails*> replicas;
    pair<TabletReplicaMap::iterator, TabletReplicaMap::iterator> range =
        tablet_replicas_.equal_range(tablet_id);
    for (;range.first != range.second; ++range.first) {
      replicas.push_back((*range.first).second);
    }

    for (TServerDetails* replica : replicas) {
      if (leader != NULL &&
          replica->instance_id.permanent_uuid() == leader->instance_id.permanent_uuid()) {
        continue;
      }
      Status s = GetReplicaStatusAndCheckIfLeader(replica, tablet_id,
                                                  MonoDelta::FromMilliseconds(100));
      if (s.IsIllegalState()) {
        followers->push_back(replica);
      }
    }
  }

  // Return the index within 'replicas' for the replica which is farthest ahead.
  int64_t GetFurthestAheadReplicaIdx(const std::string& tablet_id,
                                     const std::vector<TServerDetails*>& replicas) {
    std::vector<OpId> op_ids;
    CHECK_OK(GetLastOpIdForEachReplica(tablet_id, replicas, consensus::RECEIVED_OPID,
                                       MonoDelta::FromSeconds(10), &op_ids));

    int64 max_index = 0;
    int max_replica_index = -1;
    for (int i = 0; i < op_ids.size(); i++) {
      if (op_ids[i].index() > max_index) {
        max_index = op_ids[i].index();
        max_replica_index = i;
      }
    }

    CHECK_NE(max_replica_index, -1);

    return max_replica_index;
  }

  Status ShutdownServerWithUUID(const std::string& uuid) {
    for (int i = 0; i < cluster_->num_tablet_servers(); i++) {
      ExternalTabletServer* ts = cluster_->tablet_server(i);
      if (ts->instance_id().permanent_uuid() == uuid) {
        ts->Shutdown();
        return Status::OK();
      }
    }
    return Status::NotFound("Unable to find server with UUID", uuid);
  }

  Status RestartServerWithUUID(const std::string& uuid) {
    for (int i = 0; i < cluster_->num_tablet_servers(); i++) {
      ExternalTabletServer* ts = cluster_->tablet_server(i);
      if (ts->instance_id().permanent_uuid() == uuid) {
        ts->Shutdown();
        RETURN_NOT_OK(CheckTabletServersAreAlive(tablet_servers_.size()-1));
        RETURN_NOT_OK(ts->Restart());
        RETURN_NOT_OK(CheckTabletServersAreAlive(tablet_servers_.size()));
        return Status::OK();
      }
    }
    return Status::NotFound("Unable to find server with UUID", uuid);
  }

  // Since we're fault-tolerant we might mask when a tablet server is
  // dead. This returns Status::IllegalState() if fewer than 'num_tablet_servers'
  // are alive.
  Status CheckTabletServersAreAlive(int num_tablet_servers) {
    int live_count = 0;
    std::string error = strings::Substitute("Fewer than $0 TabletServers were alive. Dead TSs: ",
                                            num_tablet_servers);
    RpcController controller;
    for (const TabletServerMap::value_type& entry : tablet_servers_) {
      controller.Reset();
      controller.set_timeout(MonoDelta::FromSeconds(10));
      PingRequestPB req;
      PingResponsePB resp;
      Status s = entry.second->tserver_proxy->Ping(req, &resp, &controller);
      if (!s.ok()) {
        error += "\n" + entry.second->ToString() +  " (" + s.ToString() + ")";
        continue;
      }
      live_count++;
    }
    if (live_count < num_tablet_servers) {
      return Status::IllegalState(error);
    }
    return Status::OK();
  }

  virtual void TearDown() OVERRIDE {
    STLDeleteValues(&tablet_servers_);
  }

  void CreateClient(client::sp::shared_ptr<client::KuduClient>* client) {
    // Connect to the cluster.
    ASSERT_OK(client::KuduClientBuilder()
                     .add_master_server_addr(cluster_->master()->bound_rpc_addr().ToString())
                     .Build(client));
  }

  // Create a table with a single tablet, with 'num_replicas'.
  void CreateTable() {
    // The tests here make extensive use of server schemas, but we need
    // a client schema to create the table.
    client::KuduSchema client_schema(KuduSchemaFromSchema(schema_));
    gscoped_ptr<client::KuduTableCreator> table_creator(client_->NewTableCreator());
    ASSERT_OK(table_creator->table_name(kTableId)
             .schema(&client_schema)
             .set_range_partition_columns({ "key" })
             .num_replicas(FLAGS_num_replicas)
             .Create());
    ASSERT_OK(client_->OpenTable(kTableId, &table_));
  }

  // Starts an external cluster with a single tablet and a number of replicas equal
  // to 'FLAGS_num_replicas'. The caller can pass 'ts_flags' to specify non-default
  // flags to pass to the tablet servers.
  void BuildAndStart(const std::vector<std::string>& ts_flags = std::vector<std::string>(),
                     const std::vector<std::string>& master_flags = std::vector<std::string>()) {
    CreateCluster("raft_consensus-itest-cluster", ts_flags, master_flags);
    NO_FATALS(CreateClient(&client_));
    NO_FATALS(CreateTable());
    WaitForTSAndReplicas();
    CHECK_GT(tablet_replicas_.size(), 0);
    tablet_id_ = (*tablet_replicas_.begin()).first;
  }

  void AssertAllReplicasAgree(int expected_result_count) {
    ClusterVerifier v(cluster_.get());
    NO_FATALS(v.CheckCluster());
    NO_FATALS(v.CheckRowCount(kTableId, ClusterVerifier::EXACTLY, expected_result_count));
  }

  // Check for and restart any TS that have crashed.
  // Returns the number of servers restarted.
  int RestartAnyCrashedTabletServers() {
    int restarted = 0;
    for (int i = 0; i < cluster_->num_tablet_servers(); i++) {
      if (!cluster_->tablet_server(i)->IsProcessAlive()) {
        LOG(INFO) << "TS " << i << " appears to have crashed. Restarting.";
        cluster_->tablet_server(i)->Shutdown();
        CHECK_OK(cluster_->tablet_server(i)->Restart());
        restarted++;
      }
    }
    return restarted;
  }

  // Assert that no tablet servers have crashed.
  // Tablet servers that have been manually Shutdown() are allowed.
  void AssertNoTabletServersCrashed() {
    for (int i = 0; i < cluster_->num_tablet_servers(); i++) {
      if (cluster_->tablet_server(i)->IsShutdown()) continue;

      ASSERT_TRUE(cluster_->tablet_server(i)->IsProcessAlive())
                    << "Tablet server " << i << " crashed";
    }
  }

 protected:
  gscoped_ptr<ExternalMiniCluster> cluster_;
  gscoped_ptr<itest::ExternalMiniClusterFsInspector> inspect_;

  // Maps server uuid to TServerDetails
  TabletServerMap tablet_servers_;
  // Maps tablet to all replicas.
  TabletReplicaMap tablet_replicas_;

  client::sp::shared_ptr<client::KuduClient> client_;
  client::sp::shared_ptr<client::KuduTable> table_;
  std::string tablet_id_;

  ThreadSafeRandom random_;
};

}  // namespace tserver
}  // namespace kudu

#endif /* SRC_KUDU_INTEGRATION_TESTS_ITEST_UTIL_H_ */
