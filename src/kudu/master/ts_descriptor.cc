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

#include "kudu/master/ts_descriptor.h"

#include <math.h>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "kudu/common/wire_protocol.h"
#include "kudu/consensus/consensus.proxy.h"
#include "kudu/gutil/strings/substitute.h"
#include "kudu/master/master.pb.h"
#include "kudu/tserver/tserver_admin.proxy.h"
#include "kudu/util/flag_tags.h"
#include "kudu/util/net/net_util.h"
#include "kudu/util/pb_util.h"

DEFINE_int32(tserver_unresponsive_timeout_ms, 60 * 1000,
             "The period of time that a Master can go without receiving a heartbeat from a "
             "tablet server before considering it unresponsive. Unresponsive servers are not "
             "selected when assigning replicas during table creation or re-replication.");
TAG_FLAG(tserver_unresponsive_timeout_ms, advanced);

using std::make_shared;
using std::shared_ptr;

namespace kudu {
namespace master {

Status TSDescriptor::RegisterNew(const NodeInstancePB& instance,
                                 const ServerRegistrationPB& registration,
                                 shared_ptr<TSDescriptor>* desc) {
  shared_ptr<TSDescriptor> ret(make_shared<TSDescriptor>(instance.permanent_uuid()));
  RETURN_NOT_OK(ret->Register(instance, registration));
  desc->swap(ret);
  return Status::OK();
}

TSDescriptor::TSDescriptor(std::string perm_id)
    : permanent_uuid_(std::move(perm_id)),
      latest_seqno_(-1),
      last_heartbeat_(MonoTime::Now()),
      recent_replica_creations_(0),
      last_replica_creations_decay_(MonoTime::Now()),
      num_live_replicas_(0) {
}

TSDescriptor::~TSDescriptor() {
}

// Compares two repeated HostPortPB fields. Returns true if equal, false otherwise.
static bool HostPortPBsEqual(const google::protobuf::RepeatedPtrField<HostPortPB>& pb1,
                             const google::protobuf::RepeatedPtrField<HostPortPB>& pb2) {
  if (pb1.size() != pb2.size()) {
    return false;
  }

  // Do a set-based equality search.
  std::unordered_set<HostPort, HostPortHasher, HostPortEqualityPredicate> hostports1;
  std::unordered_set<HostPort, HostPortHasher, HostPortEqualityPredicate> hostports2;
  for (int i = 0; i < pb1.size(); i++) {
    HostPort hp1;
    HostPort hp2;
    if (!HostPortFromPB(pb1.Get(i), &hp1).ok()) return false;
    if (!HostPortFromPB(pb2.Get(i), &hp2).ok()) return false;
    hostports1.insert(hp1);
    hostports2.insert(hp2);
  }
  return hostports1 == hostports2;
}

Status TSDescriptor::Register(const NodeInstancePB& instance,
                              const ServerRegistrationPB& registration) {
  std::lock_guard<simple_spinlock> l(lock_);
  CHECK_EQ(instance.permanent_uuid(), permanent_uuid_);

  // TODO(KUDU-418): we don't currently support changing RPC addresses since the
  // host/port is stored persistently in each tablet's metadata.
  if (registration_ &&
      !HostPortPBsEqual(registration_->rpc_addresses(), registration.rpc_addresses())) {
    string msg = strings::Substitute(
        "Tablet server $0 is attempting to re-register with a different host/port. "
        "This is not currently supported. Old: {$1} New: {$2}",
        instance.permanent_uuid(),
        SecureShortDebugString(*registration_),
        SecureShortDebugString(registration));
    LOG(ERROR) << msg;
    return Status::InvalidArgument(msg);
  }

  if (registration.rpc_addresses().empty()) {
    return Status::InvalidArgument(
        "invalid registration: must have at least one RPC address",
        SecureShortDebugString(registration));
  }

  if (instance.instance_seqno() < latest_seqno_) {
    return Status::AlreadyPresent(
      strings::Substitute("Cannot register with sequence number $0:"
                          " Already have a registration from sequence number $1",
                          instance.instance_seqno(),
                          latest_seqno_));
  } else if (instance.instance_seqno() == latest_seqno_) {
    // It's possible that the TS registered, but our response back to it
    // got lost, so it's trying to register again with the same sequence
    // number. That's fine.
    LOG(INFO) << "Processing retry of TS registration from " << SecureShortDebugString(instance);
  }

  latest_seqno_ = instance.instance_seqno();
  registration_.reset(new ServerRegistrationPB(registration));
  ts_admin_proxy_.reset();
  consensus_proxy_.reset();

  return Status::OK();
}

void TSDescriptor::UpdateHeartbeatTime() {
  std::lock_guard<simple_spinlock> l(lock_);
  last_heartbeat_ = MonoTime::Now();
}

MonoDelta TSDescriptor::TimeSinceHeartbeat() const {
  MonoTime now(MonoTime::Now());
  std::lock_guard<simple_spinlock> l(lock_);
  return now - last_heartbeat_;
}

bool TSDescriptor::PresumedDead() const {
  return TimeSinceHeartbeat().ToMilliseconds() >= FLAGS_tserver_unresponsive_timeout_ms;
}

int64_t TSDescriptor::latest_seqno() const {
  std::lock_guard<simple_spinlock> l(lock_);
  return latest_seqno_;
}

void TSDescriptor::DecayRecentReplicaCreationsUnlocked() {
  // In most cases, we won't have any recent replica creations, so
  // we don't need to bother calling the clock, etc.
  if (recent_replica_creations_ == 0) return;

  const double kHalflifeSecs = 60;
  MonoTime now = MonoTime::Now();
  double secs_since_last_decay = (now - last_replica_creations_decay_).ToSeconds();
  recent_replica_creations_ *= pow(0.5, secs_since_last_decay / kHalflifeSecs);

  // If sufficiently small, reset down to 0 to take advantage of the fast path above.
  if (recent_replica_creations_ < 1e-12) {
    recent_replica_creations_ = 0;
  }
  last_replica_creations_decay_ = now;
}

void TSDescriptor::IncrementRecentReplicaCreations() {
  std::lock_guard<simple_spinlock> l(lock_);
  DecayRecentReplicaCreationsUnlocked();
  recent_replica_creations_ += 1;
}

double TSDescriptor::RecentReplicaCreations() {
  std::lock_guard<simple_spinlock> l(lock_);
  DecayRecentReplicaCreationsUnlocked();
  return recent_replica_creations_;
}

void TSDescriptor::GetRegistration(ServerRegistrationPB* reg) const {
  std::lock_guard<simple_spinlock> l(lock_);
  CHECK(registration_) << "No registration";
  CHECK_NOTNULL(reg)->CopyFrom(*registration_);
}

void TSDescriptor::GetNodeInstancePB(NodeInstancePB* instance_pb) const {
  std::lock_guard<simple_spinlock> l(lock_);
  instance_pb->set_permanent_uuid(permanent_uuid_);
  instance_pb->set_instance_seqno(latest_seqno_);
}

Status TSDescriptor::ResolveSockaddr(Sockaddr* addr) const {
  vector<HostPort> hostports;
  {
    std::lock_guard<simple_spinlock> l(lock_);
    for (const HostPortPB& addr : registration_->rpc_addresses()) {
      hostports.push_back(HostPort(addr.host(), addr.port()));
    }
  }

  // Resolve DNS outside the lock.
  HostPort last_hostport;
  vector<Sockaddr> addrs;
  for (const HostPort& hostport : hostports) {
    RETURN_NOT_OK(hostport.ResolveAddresses(&addrs));
    if (!addrs.empty()) {
      last_hostport = hostport;
      break;
    }
  }

  if (addrs.size() == 0) {
    return Status::NetworkError("Unable to find the TS address: ",
                                SecureDebugString(*registration_));
  }

  if (addrs.size() > 1) {
    LOG(WARNING) << "TS address " << last_hostport.ToString()
                  << " resolves to " << addrs.size() << " different addresses. Using "
                  << addrs[0].ToString();
  }
  *addr = addrs[0];
  return Status::OK();
}

Status TSDescriptor::GetTSAdminProxy(const shared_ptr<rpc::Messenger>& messenger,
                                     shared_ptr<tserver::TabletServerAdminServiceProxy>* proxy) {
  {
    std::lock_guard<simple_spinlock> l(lock_);
    if (ts_admin_proxy_) {
      *proxy = ts_admin_proxy_;
      return Status::OK();
    }
  }

  Sockaddr addr;
  RETURN_NOT_OK(ResolveSockaddr(&addr));

  std::lock_guard<simple_spinlock> l(lock_);
  if (!ts_admin_proxy_) {
    ts_admin_proxy_.reset(new tserver::TabletServerAdminServiceProxy(messenger, addr));
  }
  *proxy = ts_admin_proxy_;
  return Status::OK();
}

Status TSDescriptor::GetConsensusProxy(const shared_ptr<rpc::Messenger>& messenger,
                                       shared_ptr<consensus::ConsensusServiceProxy>* proxy) {
  {
    std::lock_guard<simple_spinlock> l(lock_);
    if (consensus_proxy_) {
      *proxy = consensus_proxy_;
      return Status::OK();
    }
  }

  Sockaddr addr;
  RETURN_NOT_OK(ResolveSockaddr(&addr));

  std::lock_guard<simple_spinlock> l(lock_);
  if (!consensus_proxy_) {
    consensus_proxy_.reset(new consensus::ConsensusServiceProxy(messenger, addr));
  }
  *proxy = consensus_proxy_;
  return Status::OK();
}

string TSDescriptor::ToString() const {
  std::lock_guard<simple_spinlock> l(lock_);
  const auto& addr = registration_->rpc_addresses(0);
  return strings::Substitute("$0 ($1:$2)", permanent_uuid_, addr.host(), addr.port());
}

} // namespace master
} // namespace kudu
