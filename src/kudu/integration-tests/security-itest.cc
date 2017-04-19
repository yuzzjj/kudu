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

#include <memory>

#include "kudu/client/client.h"
#include "kudu/client/client-test-util.h"
#include "kudu/master/master.proxy.h"
#include "kudu/integration-tests/external_mini_cluster.h"
#include "kudu/tablet/key_value_test_schema.h"
#include "kudu/rpc/messenger.h"
#include "kudu/server/server_base.proxy.h"
#include "kudu/util/test_util.h"

using kudu::client::KuduClient;
using kudu::client::KuduInsert;
using kudu::client::KuduSchema;
using kudu::client::KuduSession;
using kudu::client::KuduTable;
using kudu::client::KuduTableCreator;
using kudu::rpc::Messenger;
using std::unique_ptr;

namespace kudu {

class SecurityITest : public KuduTest {
 public:
  SecurityITest() {
    cluster_opts_.enable_kerberos = true;
    cluster_opts_.num_tablet_servers = 3;
    cluster_opts_.extra_master_flags.push_back("--rpc_trace_negotiation");
    cluster_opts_.extra_tserver_flags.push_back("--rpc_trace_negotiation");
  }
  Status StartCluster() {
    cluster_.reset(new ExternalMiniCluster(cluster_opts_));
    return cluster_->Start();
  }

  Status TrySetFlagOnTS() {
    // Make a new messenger so that we don't reuse any cached connections from
    // the minicluster startup sequence.
    auto messenger = NewMessengerOrDie();
    server::GenericServiceProxy proxy(
        messenger, cluster_->tablet_server(0)->bound_rpc_addr());

    rpc::RpcController controller;
    controller.set_timeout(MonoDelta::FromSeconds(30));
    server::SetFlagRequestPB req;
    server::SetFlagResponsePB resp;
    req.set_flag("non-existent");
    req.set_value("xx");
    return proxy.SetFlag(req, &resp, &controller);
  }

  // Create a table, insert a row, scan it back, and delete the table.
  void SmokeTestCluster();

  Status TryRegisterAsTS() {
    // Make a new messenger so that we don't reuse any cached connections from
    // the minicluster startup sequence.
    auto messenger = NewMessengerOrDie();
    master::MasterServiceProxy proxy(
        messenger, cluster_->master(0)->bound_rpc_addr());

    rpc::RpcController rpc;
    master::TSHeartbeatRequestPB req;
    master::TSHeartbeatResponsePB resp;
    req.mutable_common()->mutable_ts_instance()->set_permanent_uuid("x");
    req.mutable_common()->mutable_ts_instance()->set_instance_seqno(1);
    return proxy.TSHeartbeat(req, &resp, &rpc);
  }

 private:
  std::shared_ptr<Messenger> NewMessengerOrDie() {
    std::shared_ptr<Messenger> messenger;
    CHECK_OK(rpc::MessengerBuilder("test-messenger")
             .set_num_reactors(1)
             .set_max_negotiation_threads(1)
             .Build(&messenger));
    return messenger;
  }

 protected:
  ExternalMiniClusterOptions cluster_opts_;
  unique_ptr<ExternalMiniCluster> cluster_;
};

void SecurityITest::SmokeTestCluster() {
  const char* kTableName = "test-table";
  client::sp::shared_ptr<KuduClient> client;
  ASSERT_OK(cluster_->CreateClient(nullptr, &client));

  // Create a table.
  KuduSchema schema = client::KuduSchemaFromSchema(CreateKeyValueTestSchema());
  gscoped_ptr<KuduTableCreator> table_creator(client->NewTableCreator());
  ASSERT_OK(table_creator->table_name(kTableName)
            .set_range_partition_columns({ "key" })
            .schema(&schema)
            .num_replicas(3)
            .Create());

  // Insert a row.
  client::sp::shared_ptr<KuduTable> table;
  ASSERT_OK(client->OpenTable(kTableName, &table));
  client::sp::shared_ptr<KuduSession> session = client->NewSession();
  session->SetTimeoutMillis(60000);
  unique_ptr<KuduInsert> ins(table->NewInsert());
  ASSERT_OK(ins->mutable_row()->SetInt32(0, 12345));
  ASSERT_OK(ins->mutable_row()->SetInt32(1, 54321));
  ASSERT_OK(session->Apply(ins.release()));
  FlushSessionOrDie(session);

  // Read it back.
  ASSERT_EQ(1, CountTableRows(table.get()));

  // Delete the table.
  ASSERT_OK(client->DeleteTable(kTableName));
}

// Test creating a table, writing some data, reading data, and dropping
// the table.
TEST_F(SecurityITest, SmokeTestAsAuthorizedUser) {
  ASSERT_OK(StartCluster());

  ASSERT_OK(cluster_->kdc()->Kinit("test-user"));
  NO_FATALS(SmokeTestCluster());

  // Non-superuser clients should not be able to set flags.
  Status s = TrySetFlagOnTS();
  ASSERT_EQ("Remote error: Not authorized: unauthorized access to method: SetFlag",
            s.ToString());

  // Nor should they be able to send TS RPCs.
  s = TryRegisterAsTS();
  ASSERT_EQ("Remote error: Not authorized: unauthorized access to method: TSHeartbeat",
            s.ToString());
}

#ifndef __APPLE__
// Test trying to access the cluster with no Kerberos credentials at all.
// This test is ignored on macOS because the system Kerberos implementation
// (Heimdal) caches the non-existence of client credentials, which causes
// subsequent tests to fail.
TEST_F(SecurityITest, TestNoKerberosCredentials) {
  ASSERT_OK(StartCluster());
  ASSERT_OK(cluster_->kdc()->Kdestroy());

  client::sp::shared_ptr<KuduClient> client;
  Status s = cluster_->CreateClient(nullptr, &client);
  // The error message differs on el6 from newer krb5 implementations,
  // so we'll check for either one.
  ASSERT_STR_MATCHES(s.ToString(),
                     "Not authorized: Could not connect to the cluster: "
                     "Client connection negotiation failed: client connection "
                     "to .*: (No Kerberos credentials available|"
                     "Credentials cache file.*not found)");
}
#endif

// Test cluster access by a user who is not authorized as a client.
TEST_F(SecurityITest, TestUnauthorizedClientKerberosCredentials) {
  ASSERT_OK(StartCluster());
  ASSERT_OK(cluster_->kdc()->Kinit("joe-interloper"));
  client::sp::shared_ptr<KuduClient> client;
  Status s = cluster_->CreateClient(nullptr, &client);
  ASSERT_EQ("Remote error: Could not connect to the cluster: "
            "Not authorized: unauthorized access to method: ConnectToMaster",
            s.ToString());
}

// Test superuser actions when authorized as a superuser.
TEST_F(SecurityITest, TestAuthorizedSuperuser) {
  ASSERT_OK(StartCluster());

  ASSERT_OK(cluster_->kdc()->Kinit("test-admin"));

  // Superuser can set flags.
  ASSERT_OK(TrySetFlagOnTS());

  // Even superusers can't pretend to be tablet servers.
  Status s = TryRegisterAsTS();

  ASSERT_EQ("Remote error: Not authorized: unauthorized access to method: TSHeartbeat",
            s.ToString());

}

// Test that the web UIs can be entirely disabled, for users who feel they
// are a security risk.
TEST_F(SecurityITest, TestDisableWebUI) {
  cluster_opts_.extra_master_flags.push_back("--webserver_enabled=0");
  cluster_opts_.extra_tserver_flags.push_back("--webserver_enabled=0");
  ASSERT_OK(StartCluster());
  NO_FATALS(SmokeTestCluster());
}

// Test disabling authentication and encryption.
TEST_F(SecurityITest, TestDisableAuthenticationEncryption) {
  cluster_opts_.extra_master_flags.push_back("--rpc_authentication=disabled");
  cluster_opts_.extra_tserver_flags.push_back("--rpc_authentication=disabled");
  cluster_opts_.extra_master_flags.push_back("--rpc_encryption=disabled");
  cluster_opts_.extra_tserver_flags.push_back("--rpc_encryption=disabled");
  cluster_opts_.enable_kerberos = false;
  ASSERT_OK(StartCluster());
  NO_FATALS(SmokeTestCluster());
}

} // namespace kudu
