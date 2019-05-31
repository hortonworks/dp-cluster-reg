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

from dp_cluster_reg.base import BaseClusterManager
from dp_cluster_reg.rest import Credentials, CMRestClient
from .cluster import CMCluster


class ClouderaManager(BaseClusterManager):
    """ Base class for  cluster """

    def __init__(
            self,
            base_url,
            credentials=Credentials(
                'admin',
                'admin'),
            api_version='v19'):
        self.base_url = base_url
        self.client = CMRestClient(base_url / 'api' / api_version, credentials)
        self.api_version = api_version
        self.clusters = self._find_clusters_detail()
        self.total_clusters = self._total_clusters()
        self.internal_host = self._find_internal_host_name()

    def _find_clusters_detail(self):
        clusters = self._find_clusters()
        return [CMCluster(cluster, self.client) for cluster in clusters]

    def _find_repository_version(self, cluster_name):
        pass

    def _total_clusters(self):
        return len(self.clusters) if self.clusters else 0

    def _find_clusters(self):
        response = self.client.cluster_api_instance().read_clusters(view='full')  # noqa
        return response.items
    
    def _find_internal_host_name(self):
        pass

    def kerberos_enabled(self):
        resp = self.client.cm_api_instance().get_kerberos_info()
        if resp.kerberized:
            return True
        return False

    def knox_rules_defined(self):
        props_to_check = ['PROXYUSER_KNOX_GROUPS',
                          'PROXYUSER_KNOX_HOSTS',
                          'PROXYUSER_KNOX_PRINCIPAL',
                          'PROXYUSER_KNOX_USERS']
        resp = self.client.cm_api_instance().get_config()
        props = [data.name for data in resp.items]
        if all(elem in props for elem in props_to_check):
            return True
        return False
