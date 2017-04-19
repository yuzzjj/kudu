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

#include "kudu/util/pstack_watcher.h"

#include <memory>
#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "kudu/gutil/strings/substitute.h"
#include "kudu/util/env.h"
#include "kudu/util/errno.h"
#include "kudu/util/status.h"
#include "kudu/util/subprocess.h"

namespace kudu {

using std::shared_ptr;
using std::string;
using std::vector;
using strings::Substitute;

PstackWatcher::PstackWatcher(MonoDelta timeout)
    : timeout_(std::move(timeout)), running_(true), cond_(&lock_) {
  CHECK_OK(Thread::Create("pstack_watcher", "pstack_watcher",
                 boost::bind(&PstackWatcher::Run, this), &thread_));
}

PstackWatcher::~PstackWatcher() {
  Shutdown();
}

void PstackWatcher::Shutdown() {
  {
    MutexLock guard(lock_);
    running_ = false;
    cond_.Broadcast();
  }
  if (thread_) {
    CHECK_OK(ThreadJoiner(thread_.get()).Join());
    thread_.reset();
  }
}

bool PstackWatcher::IsRunning() const {
  MutexLock guard(lock_);
  return running_;
}

void PstackWatcher::Wait() const {
  MutexLock lock(lock_);
  while (running_) {
    cond_.Wait();
  }
}

void PstackWatcher::Run() {
  MutexLock guard(lock_);
  if (!running_) return;
  cond_.TimedWait(timeout_);
  if (!running_) return;

  WARN_NOT_OK(DumpStacks(DUMP_FULL), "Unable to print pstack from watcher");
  running_ = false;
  cond_.Broadcast();
}

Status PstackWatcher::HasProgram(const char* progname) {
  string which("which");
  vector<string> argv;
  argv.push_back(which);
  argv.push_back(progname);
  Subprocess proc(which, argv);
  proc.DisableStderr();
  proc.DisableStdout();
  RETURN_NOT_OK_PREPEND(proc.Start(),
      Substitute("HasProgram($0): error running 'which'", progname));
  RETURN_NOT_OK(proc.Wait());
  int exit_status;
  string exit_info;
  RETURN_NOT_OK(proc.GetExitStatus(&exit_status, &exit_info));
  if (exit_status == 0) {
    return Status::OK();
  }
  return Status::NotFound(Substitute("can't find $0: $1", progname, exit_info));
}

Status PstackWatcher::DumpStacks(int flags) {
  return DumpPidStacks(getpid(), flags);
}

Status PstackWatcher::DumpPidStacks(pid_t pid, int flags) {

  // Prefer GDB if available; it gives us line numbers and thread names.
  if (HasProgram("gdb").ok()) {
    return RunGdbStackDump(pid, flags);
  }

  // Otherwise, try to use pstack or gstack.
  const char *progname = nullptr;
  if (HasProgram("pstack").ok()) {
    progname = "pstack";
  } else if (HasProgram("gstack").ok()) {
    progname = "gstack";
  }

  if (!progname) {
    return Status::ServiceUnavailable("Neither gdb, pstack, nor gstack appears to be installed.");
  }
  return RunPstack(progname, pid);
}

Status PstackWatcher::RunGdbStackDump(pid_t pid, int flags) {
  // Command: gdb -quiet -batch -nx -ex cmd1 -ex cmd2 /proc/$PID/exe $PID
  string prog("gdb");
  vector<string> argv;
  argv.push_back(prog);
  // Don't print introductory version/copyright messages.
  argv.push_back("-quiet");
  // Exit after processing all of the commands below.
  argv.push_back("-batch");
  // Don't run commands from .gdbinit
  argv.push_back("-nx");
  // On RHEL6 and older Ubuntu, we occasionally would see gdb spin forever
  // trying to collect backtraces. Setting a backtrace limit is a reasonable
  // workaround, since we don't really expect >100-deep stacks anyway.
  //
  // See https://bugs.launchpad.net/ubuntu/+source/gdb/+bug/434168
  argv.push_back("-ex");
  argv.push_back("set backtrace limit 100");
  argv.push_back("-ex");
  argv.push_back("set print pretty on");
  argv.push_back("-ex");
  argv.push_back("info threads");
  argv.push_back("-ex");
  argv.push_back("thread apply all bt");
  if (flags & DUMP_FULL) {
    argv.push_back("-ex");
    argv.push_back("thread apply all bt full");
  }
  string executable;
  Env* env = Env::Default();
  RETURN_NOT_OK(env->GetExecutablePath(&executable));
  argv.push_back(executable);
  argv.push_back(Substitute("$0", pid));
  return RunStackDump(prog, argv);
}

Status PstackWatcher::RunPstack(const std::string& progname, pid_t pid) {
  string prog(progname);
  string pid_string(Substitute("$0", pid));
  vector<string> argv;
  argv.push_back(prog);
  argv.push_back(pid_string);
  return RunStackDump(prog, argv);
}

Status PstackWatcher::RunStackDump(const string& prog, const vector<string>& argv) {
  printf("************************ BEGIN STACKS **************************\n");
  if (fflush(stdout) == EOF) {
    return Status::IOError("Unable to flush stdout", ErrnoToString(errno), errno);
  }
  Subprocess pstack_proc(prog, argv);
  RETURN_NOT_OK_PREPEND(pstack_proc.Start(), "RunStackDump proc.Start() failed");
  if (::close(pstack_proc.ReleaseChildStdinFd()) == -1) {
    return Status::IOError("Unable to close child stdin", ErrnoToString(errno), errno);
  }
  RETURN_NOT_OK_PREPEND(pstack_proc.Wait(), "RunStackDump proc.Wait() failed");
  int exit_code;
  string exit_info;
  RETURN_NOT_OK_PREPEND(pstack_proc.GetExitStatus(&exit_code, &exit_info),
                        "RunStackDump proc.GetExitStatus() failed");
  if (exit_code != 0) {
    return Status::RuntimeError("RunStackDump proc.Wait() error", exit_info);
  }
  printf("************************* END STACKS ***************************\n");
  if (fflush(stdout) == EOF) {
    return Status::IOError("Unable to flush stdout", ErrnoToString(errno), errno);
  }

  return Status::OK();
}

} // namespace kudu
