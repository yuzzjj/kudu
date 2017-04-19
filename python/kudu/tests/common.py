#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import division

import json
import fnmatch
import os
import shutil
import subprocess
import tempfile
import time
import socket

import kudu
from kudu.client import Partitioning

class KuduTestBase(object):

    """
    Base test class that will start a configurable number of master and
    tablet servers.
    """

    BASE_PORT = 37000
    NUM_TABLET_SERVERS = 3
    TSERVER_START_TIMEOUT_SECS = 10
    NUM_MASTER_SERVERS = 3

    @classmethod
    def start_cluster(cls):
        local_path = tempfile.mkdtemp(dir=os.getenv("TEST_TMPDIR"))
        kudu_build = os.getenv("KUDU_BUILD")
        if not kudu_build:
            kudu_build = os.path.join(os.getenv("KUDU_HOME"), "build", "latest")
        bin_path = "{0}/bin".format(kudu_build)

        master_hosts = []
        master_ports = []

        # We need to get the port numbers for the masters before starting them
        # so that we can appropriately configure a multi-master.
        for m in range(cls.NUM_MASTER_SERVERS):
            master_hosts.append('127.0.0.1')
            # This introduces a race
            s = socket.socket()
            s.bind(('', 0))
            master_ports.append(s.getsockname()[1])
            s.close()

        multi_master_string = ','.join('{0}:{1}'.format(host, port)
                                       for host, port
                                       in zip(master_hosts, master_ports))

        for m in range(cls.NUM_MASTER_SERVERS):
            os.makedirs("{0}/master/{1}".format(local_path, m))
            os.makedirs("{0}/master/{1}/data".format(local_path, m))
            os.makedirs("{0}/master/{1}/logs".format(local_path, m))


            path = [
                "{0}/kudu-master".format(bin_path),
                "-unlock_unsafe_flags",
                "-unlock_experimental_flags",
                "-rpc_server_allow_ephemeral_ports",
                "-rpc_bind_addresses=0.0.0.0:{0}".format(master_ports[m]),
                "-fs_wal_dir={0}/master/{1}/data".format(local_path, m),
                "-fs_data_dirs={0}/master/{1}/data".format(local_path, m),
                "-log_dir={0}/master/{1}/logs".format(local_path, m),
                "-logtostderr",
                "-webserver_port=0",
                "-master_addresses={0}".format(multi_master_string),
                # Only make one replica so that our tests don't need to worry about
                # setting consistency modes.
                "-default_num_replicas=1"
            ]

            p = subprocess.Popen(path, shell=False)
            fid = open("{0}/master/{1}/kudu-master.pid".format(local_path, m), "w+")
            fid.write("{0}".format(p.pid))
            fid.close()

        for m in range(cls.NUM_TABLET_SERVERS):
            os.makedirs("{0}/ts/{1}".format(local_path, m))
            os.makedirs("{0}/ts/{1}/logs".format(local_path, m))

            path = [
                "{0}/kudu-tserver".format(bin_path),
                "-unlock_unsafe_flags",
                "-unlock_experimental_flags",
                "-rpc_server_allow_ephemeral_ports",
                "-rpc_bind_addresses=0.0.0.0:0",
                "-tserver_master_addrs={0}".format(multi_master_string),
                "-webserver_port=0",
                "-log_dir={0}/ts/{1}/logs".format(local_path, m),
                "-logtostderr",
                "-fs_data_dirs={0}/ts/{1}/data".format(local_path, m),
                "-fs_wal_dir={0}/ts/{1}/data".format(local_path, m),
            ]
            p = subprocess.Popen(path, shell=False)
            tserver_pid = "{0}/ts/{1}/kudu-tserver.pid".format(local_path, m)
            fid = open(tserver_pid, "w+")
            fid.write("{0}".format(p.pid))
            fid.close()

        return local_path, master_hosts, master_ports

    @classmethod
    def stop_cluster(cls, path):
        for root, dirnames, filenames in os.walk('{0}/..'.format(path)):
            for filename in fnmatch.filter(filenames, '*.pid'):
                with open(os.path.join(root, filename)) as fid:
                    a = fid.read()
                    r = subprocess.Popen(["kill", "{0}".format(a)])
                    r.wait()
                    os.remove(os.path.join(root, filename))
        shutil.rmtree(path, True)

    @classmethod
    def setUpClass(cls):
        cls.cluster_path, cls.master_hosts, cls.master_ports = cls.start_cluster()
        time.sleep(1)

        cls.client = kudu.connect(cls.master_hosts, cls.master_ports)

        # Wait for all tablet servers to start with the configured timeout
        timeout = time.time() + cls.TSERVER_START_TIMEOUT_SECS
        while len(cls.client.list_tablet_servers()) < cls.NUM_TABLET_SERVERS:
            if time.time() > timeout:
                raise TimeoutError(
                    "Tablet servers took too long to start. Timeout set to {}"
                                   .format(cls.TSERVER_START_TIMEOUT_SECS))
            # Sleep 50 milliseconds to avoid tight-looping rpc
            time.sleep(0.05)

        cls.schema = cls.example_schema()
        cls.partitioning = cls.example_partitioning()

        cls.ex_table = 'example-table'
        if cls.client.table_exists(cls.ex_table):
            cls.client.delete_table(cls.ex_table)
        cls.client.create_table(cls.ex_table, cls.schema, cls.partitioning)

    @classmethod
    def tearDownClass(cls):
        cls.stop_cluster(cls.cluster_path)

    @classmethod
    def example_schema(cls):
        builder = kudu.schema_builder()
        builder.add_column('key', kudu.int32, nullable=False)
        builder.add_column('int_val', kudu.int32)
        builder.add_column('string_val', kudu.string, default='nothing')
        builder.add_column('unixtime_micros_val', kudu.unixtime_micros)
        builder.set_primary_keys(['key'])

        return builder.build()

    @classmethod
    def example_partitioning(cls):
        return Partitioning().set_range_partition_columns(['key'])
