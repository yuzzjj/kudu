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
#ifndef KUDU_MASTER_SYS_CATALOG_H_
#define KUDU_MASTER_SYS_CATALOG_H_

#include <functional>
#include <set>
#include <string>
#include <vector>

#include "kudu/consensus/metadata.pb.h"
#include "kudu/master/master.pb.h"
#include "kudu/tablet/tablet_peer.h"
#include "kudu/util/status.h"

namespace kudu {

class Schema;
class FsManager;

namespace tserver {
class WriteRequestPB;
class WriteResponsePB;
}

namespace master {

class Master;
class TableInfo;
class TabletInfo;
struct MasterOptions;

// The SysCatalogTable has two separate visitors because the tables
// data must be loaded into memory before the tablets data.
class TableVisitor {
 public:
  virtual Status VisitTable(const std::string& table_id,
                            const SysTablesEntryPB& metadata) = 0;
};

class TabletVisitor {
 public:
  virtual Status VisitTablet(const std::string& table_id,
                             const std::string& tablet_id,
                             const SysTabletsEntryPB& metadata) = 0;
};

// Visitor for TSK-related (Token Signing Key) entries. Actually, only the
// public part of those are stored in the system catalog table. That information
// is preserved to allow any master to verify token which might be signed
// by current or former master leader.
class TskEntryVisitor {
 public:
  virtual Status Visit(const std::string& entry_id,
                       const SysTskEntryPB& metadata) = 0;
};

// SysCatalogTable is a Kudu table that keeps track of the following
// system information:
//   * table metadata
//   * tablet metadata
//   * root CA (certificate authority) certificate of the Kudu IPKI
//   * Kudu IPKI root CA cert's private key
//   * TSK (Token Signing Key) entries
//
// The essential properties of the SysCatalogTable are:
//   * SysCatalogTable has only one tablet.
//   * SysCatalogTable is managed by the master and not exposed to the user
//     as a "normal table", instead we have Master APIs to query the table.
class SysCatalogTable {
 public:
  // Magic ID of the system tablet.
  static const char* const kSysCatalogTabletId;

  // Root certificate authority (CA) entry identifier in the system table.
  // There should be no more than one entry of this type in the system table.
  static const char* const kSysCertAuthorityEntryId;

  typedef Callback<Status()> ElectedLeaderCallback;

  enum CatalogEntryType {
    TABLES_ENTRY = 1,
    TABLETS_ENTRY = 2,
    CERT_AUTHORITY_INFO = 3,  // Kudu's root certificate authority entry.
    TSK_ENTRY = 4,            // Token Signing Key entry.
  };

  // 'leader_cb_' is invoked whenever this node is elected as a leader
  // of the consensus configuration for this tablet, including for local standalone
  // master consensus configurations. It used to initialize leader state, submit any
  // leader-specific tasks and so forth.
  //
  /// NOTE: Since 'leader_cb_' is invoked synchronously and can block
  // the consensus configuration's progress, any long running tasks (e.g., scanning
  // tablets) should be performed asynchronously (by, e.g., submitting
  // them to a to a separate threadpool).
  SysCatalogTable(Master* master, MetricRegistry* metrics,
                  ElectedLeaderCallback leader_cb);

  ~SysCatalogTable();

  // Allow for orderly shutdown of tablet peer, etc.
  void Shutdown();

  // Load the Metadata from disk, and initialize the TabletPeer for the sys-table
  Status Load(FsManager *fs_manager);

  // Create the new Metadata and initialize the TabletPeer for the sys-table.
  Status CreateNew(FsManager *fs_manager);

  // Perform a series of table/tablet actions in one WriteTransaction.
  struct Actions {
    Actions();

    TableInfo* table_to_add;
    TableInfo* table_to_update;
    TableInfo* table_to_delete;
    std::vector<TabletInfo*> tablets_to_add;
    std::vector<TabletInfo*> tablets_to_update;
    std::vector<TabletInfo*> tablets_to_delete;
  };
  Status Write(const Actions& actions);

  // Scan of the table-related entries.
  Status VisitTables(TableVisitor* visitor);

  // Scan of the tablet-related entries.
  Status VisitTablets(TabletVisitor* visitor);

  // Scan for TSK-related entries in the system table.
  Status VisitTskEntries(TskEntryVisitor* visitor);

  // Retrive the CA entry (private key and certificate) from the system table.
  Status GetCertAuthorityEntry(SysCertAuthorityEntryPB* entry);

  // Add root CA entry (private key and certificate) into the system table.
  // There should be no more than one CA entry in the system table.
  Status AddCertAuthorityEntry(const SysCertAuthorityEntryPB& entry);

  // Add TSK (Token Signing Key) entry into the system table.
  Status AddTskEntry(const SysTskEntryPB& entry);

  // Remove TSK (Token Signing Key) entries with the specified entry identifiers
  // (as in 'entry_id' column) from the system table.
  Status RemoveTskEntries(const std::set<std::string>& entry_ids);

 private:
  FRIEND_TEST(MasterTest, TestMasterMetadataConsistentDespiteFailures);
  DISALLOW_COPY_AND_ASSIGN(SysCatalogTable);

  friend class CatalogManager;

  const char *table_name() const { return "sys.catalog"; }
  const char *table_id() const { return "sys.catalog.id"; }

  // Return the schema of the table.
  // NOTE: This is the "server-side" schema, so it must have the column IDs.
  Schema BuildTableSchema();

  // Returns 'Status::OK()' if the WriteTranasction completed
  Status SyncWrite(const tserver::WriteRequestPB *req, tserver::WriteResponsePB *resp);

  void SysCatalogStateChanged(const std::string& tablet_id, const std::string& reason);

  Status SetupTablet(const scoped_refptr<tablet::TabletMetadata>& metadata);

  // Use the master options to generate a new consensus configuration.
  // In addition, resolve all UUIDs of this consensus configuration.
  Status CreateDistributedConfig(const MasterOptions& options,
                                 consensus::RaftConfigPB* committed_config);

  const scoped_refptr<tablet::TabletPeer>& tablet_peer() const {
    return tablet_peer_;
  }

  std::string tablet_id() const {
    return tablet_peer_->tablet_id();
  }

  // Conventional "T xxx P xxxx..." prefix for logging.
  std::string LogPrefix() const;

  // Waits for the tablet to reach 'RUNNING' state.
  //
  // Contrary to tablet servers, in master we actually wait for the master tablet
  // to become online synchronously, this allows us to fail fast if something fails
  // and shouldn't induce the all-workers-blocked-waiting-for-tablets problem
  // that we've seen in tablet servers since the master only has to boot a few
  // tablets.
  Status WaitUntilRunning();

  template<typename T>
  Status GetEntryFromRow(const RowBlockRow& row,
                         std::string* entry_id, T* entry_data) const;

  template<typename T, CatalogEntryType entry_type>
  Status ProcessRows(std::function<Status(const std::string&, const T&)>) const;

  // Tablet related private methods.

  // Add dirty tablet data to the given row operations.
  Status AddTabletsToPB(const std::vector<TabletInfo*>& tablets,
                        RowOperationsPB::Type op_type,
                        RowOperationsPB* ops) const;

  // Initializes the RaftPeerPB for the local peer.
  // Crashes due to an invariant check if the rpc server is not running.
  void InitLocalRaftPeerPB();

  // Add an operation to a write adding/updating/deleting a table or tablet.
  void ReqAddTable(tserver::WriteRequestPB* req, const TableInfo* table);
  void ReqUpdateTable(tserver::WriteRequestPB* req, const TableInfo* table);
  void ReqDeleteTable(tserver::WriteRequestPB* req, const TableInfo* table);
  void ReqAddTablets(tserver::WriteRequestPB* req,
                     const std::vector<TabletInfo*>& tablets);
  void ReqUpdateTablets(tserver::WriteRequestPB* req,
                        const std::vector<TabletInfo*>& tablets);
  void ReqDeleteTablets(tserver::WriteRequestPB* req,
                        const std::vector<TabletInfo*>& tablets);

  static string TskSeqNumberToEntryId(int64_t seq_number);

  // Special string injected into SyncWrite() random failures (if enabled).
  //
  // Only useful for tests.
  static const char* const kInjectedFailureStatusMsg;

  // Table schema, without IDs, used to send messages to the TabletPeer
  Schema schema_;
  Schema key_schema_;

  MetricRegistry* metric_registry_;

  gscoped_ptr<ThreadPool> apply_pool_;

  scoped_refptr<tablet::TabletPeer> tablet_peer_;

  Master* master_;

  ElectedLeaderCallback leader_cb_;

  consensus::RaftPeerPB local_peer_pb_;
};

} // namespace master
} // namespace kudu

#endif
