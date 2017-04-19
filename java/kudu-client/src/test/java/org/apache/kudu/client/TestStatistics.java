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

import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.kudu.client.Statistics.Statistic;

public class TestStatistics extends BaseKuduTest {

  private static final String TABLE_NAME = TestStatistics.class.getName() + "-"
      + System.currentTimeMillis();
  private static KuduTable table;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    BaseKuduTest.setUpBeforeClass();
    CreateTableOptions options = getBasicCreateTableOptions().setNumReplicas(1);
    table = createTable(TABLE_NAME, basicSchema, options);
  }

  @Test(timeout = 10000)
  public void test() throws Exception {
    KuduSession session = syncClient.newSession();
    session.setFlushMode(SessionConfiguration.FlushMode.MANUAL_FLUSH);
    int rowCount = 20;
    for (int i = 0; i < rowCount; i++) {
      Insert insert = createBasicSchemaInsert(table, i);
      session.apply(insert);
      if (i % 2 == 1) {
        session.flush();
      }
    }
    Statistics statistics = syncClient.getStatistics();
    assertEquals(rowCount / 2, statistics.getClientStatistic(Statistic.WRITE_RPCS));
    assertEquals(rowCount, statistics.getClientStatistic(Statistic.WRITE_OPS));
    assertEquals(0, statistics.getClientStatistic(Statistic.RPC_ERRORS));
    assertEquals(0, statistics.getClientStatistic(Statistic.OPS_ERRORS));

    // Use default flush mode.
    session.setFlushMode(SessionConfiguration.FlushMode.AUTO_FLUSH_SYNC);
    // Insert duplicate rows, expect to get ALREADY_PRESENT error.
    long byteSize = 0;
    for (int i = 0; i < rowCount; i++) {
      Insert insert = createBasicSchemaInsert(table, i);
      session.apply(insert);
      byteSize += insert.getRowOperationSizeBytes();
    }
    assertEquals(rowCount + rowCount / 2, statistics.getClientStatistic(Statistic.WRITE_RPCS));
    assertEquals(rowCount, statistics.getClientStatistic(Statistic.WRITE_OPS));
    assertEquals(0, statistics.getClientStatistic(Statistic.RPC_ERRORS));
    assertEquals(rowCount, statistics.getClientStatistic(Statistic.OPS_ERRORS));
    assertEquals(byteSize * 2, statistics.getClientStatistic(Statistic.BYTES_WRITTEN));

    assertEquals(1, statistics.getTableSet().size());
    assertEquals(1, statistics.getTabletSet().size());
  }
}
