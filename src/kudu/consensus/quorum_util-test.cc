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

#include <glog/logging.h>
#include "kudu/consensus/quorum_util.h"

#include "kudu/consensus/opid_util.h"
#include "kudu/util/test_util.h"

namespace kudu {
namespace consensus {

using std::string;

static void SetPeerInfo(const string& uuid,
                        RaftPeerPB::MemberType type,
                        RaftPeerPB* peer) {
  peer->set_permanent_uuid(uuid);
  peer->set_member_type(type);
  peer->mutable_last_known_addr()->set_host(uuid + ".example.com");
}

TEST(QuorumUtilTest, TestMemberExtraction) {
  RaftConfigPB config;
  SetPeerInfo("A", RaftPeerPB::VOTER, config.add_peers());
  SetPeerInfo("B", RaftPeerPB::VOTER, config.add_peers());
  SetPeerInfo("C", RaftPeerPB::VOTER, config.add_peers());

  // Basic test for GetRaftConfigMember().
  RaftPeerPB peer_pb;
  Status s = GetRaftConfigMember(config, "invalid", &peer_pb);
  ASSERT_TRUE(s.IsNotFound()) << s.ToString();
  ASSERT_OK(GetRaftConfigMember(config, "A", &peer_pb));
  ASSERT_EQ("A", peer_pb.permanent_uuid());

  // Basic test for GetRaftConfigLeader().
  ConsensusStatePB cstate;
  *cstate.mutable_config() = config;
  s = GetRaftConfigLeader(cstate, &peer_pb);
  ASSERT_TRUE(s.IsNotFound()) << s.ToString();
  cstate.set_leader_uuid("B");
  ASSERT_OK(GetRaftConfigLeader(cstate, &peer_pb));
  ASSERT_EQ("B", peer_pb.permanent_uuid());
}

TEST(QuorumUtilTest, TestDiffConsensusStates) {
  ConsensusStatePB old_cs;
  SetPeerInfo("A", RaftPeerPB::VOTER, old_cs.mutable_config()->add_peers());
  SetPeerInfo("B", RaftPeerPB::VOTER, old_cs.mutable_config()->add_peers());
  SetPeerInfo("C", RaftPeerPB::VOTER, old_cs.mutable_config()->add_peers());
  old_cs.set_current_term(1);
  old_cs.set_leader_uuid("A");
  old_cs.mutable_config()->set_opid_index(1);

  // Simple case of no change.
  EXPECT_EQ("no change",
            DiffConsensusStates(old_cs, old_cs));

  // Simulate a leader change.
  {
    auto new_cs = old_cs;
    new_cs.set_leader_uuid("B");
    new_cs.set_current_term(2);

    EXPECT_EQ("term changed from 1 to 2, "
              "leader changed from A (A.example.com) to B (B.example.com)",
              DiffConsensusStates(old_cs, new_cs));
  }

  // Simulate eviction of a peer.
  {
    auto new_cs = old_cs;
    new_cs.mutable_config()->set_opid_index(2);
    new_cs.mutable_config()->mutable_peers()->RemoveLast();

    EXPECT_EQ("config changed from index 1 to 2, "
              "VOTER C (C.example.com) evicted",
              DiffConsensusStates(old_cs, new_cs));
  }

  // Simulate addition of a peer.
  {
    auto new_cs = old_cs;
    new_cs.mutable_config()->set_opid_index(2);
    SetPeerInfo("D", RaftPeerPB::NON_VOTER, new_cs.mutable_config()->add_peers());

    EXPECT_EQ("config changed from index 1 to 2, "
              "NON_VOTER D (D.example.com) added",
              DiffConsensusStates(old_cs, new_cs));
  }

  // Simulate change of a peer's member type.
  {
    auto new_cs = old_cs;
    new_cs.mutable_config()->set_opid_index(2);
    new_cs.mutable_config()->mutable_peers()->Mutable(2)->set_member_type(RaftPeerPB::NON_VOTER);

    EXPECT_EQ("config changed from index 1 to 2, "
              "C (C.example.com) changed from VOTER to NON_VOTER",
              DiffConsensusStates(old_cs, new_cs));
  }

  // Simulate change from no leader to a leader
  {
    auto no_leader_cs = old_cs;
    no_leader_cs.clear_leader_uuid();
    auto new_cs = old_cs;
    new_cs.set_current_term(2);

    EXPECT_EQ("term changed from 1 to 2, "
              "leader changed from <none> to A (A.example.com)",
              DiffConsensusStates(no_leader_cs, new_cs));
  }

}

} // namespace consensus
} // namespace kudu
