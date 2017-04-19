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
package org.apache.kudu.client;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestRequestTracker {

  @Test(timeout = 10000)
  public void test() {
    RequestTracker tracker = new RequestTracker("test");

    // A new tracker should have no incomplete RPCs.
    assertEquals(RequestTracker.NO_SEQ_NO, tracker.firstIncomplete());

    int max = 10;

    for (int i = 0; i < max; i++) {
      tracker.newSeqNo();
    }

    // The first RPC is the incomplete one.
    assertEquals(1, tracker.firstIncomplete());

    // Mark the first as complete, incomplete should advance by 1.
    tracker.rpcCompleted(1);
    assertEquals(2, tracker.firstIncomplete());

    // Mark the RPC in the middle as complete, first incomplete doesn't change.
    tracker.rpcCompleted(5);
    assertEquals(2, tracker.firstIncomplete());

    // Mark the first half as complete.
    // Note that we're also testing that rpcCompleted is idempotent.
    for (int i = 1; i < max / 2; i++) {
      tracker.rpcCompleted(i);
    }

    assertEquals(6, tracker.firstIncomplete());

    // Get a few more sequence numbers.
    long lastSeqNo = 0;
    for (int i = max / 2; i <= max; i++) {
      lastSeqNo = tracker.newSeqNo();
    }

    // Mark them all as complete except the last one.
    while (tracker.firstIncomplete() != lastSeqNo) {
      tracker.rpcCompleted(tracker.firstIncomplete());
    }

    assertEquals(lastSeqNo, tracker.firstIncomplete());
    tracker.rpcCompleted(lastSeqNo);

    // Test that we get back to NO_SEQ_NO after marking them all.
    assertEquals(RequestTracker.NO_SEQ_NO, tracker.firstIncomplete());
  }
}
