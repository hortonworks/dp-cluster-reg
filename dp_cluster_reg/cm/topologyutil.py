# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from dp_cluster_reg.base import TopologyUtil


class CMTopologyUtil(TopologyUtil):
    def __init__(self, cm, role_names):
        self.cm = cm
        self.role_names = role_names

    def ranger_url(self):
        pass

    def atlas_url(self):
        pass

    def dpprofiler_url(self):
        pass

    def beacon_url(self):
        pass

    def streamsmsgmgr_url(self):
        pass

    def host_name(self, service_name, component_name):
        pass

    def cluster_manager(self):
        protocol = self.cm.base_url.protocol()
        netloc = self.cm.base_url.netloc()
        url = "%s://%s" % (protocol, netloc)
        return self.role('CM-API', url)
