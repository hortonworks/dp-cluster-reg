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

    def current_stack_version(self):
        pass

    def enable_trusted_proxy_for_ranger(self):
        pass

    def enable_trusted_proxy_for_atlas(self):
        pass

    def enable_trusted_proxy_for_beacon(self):
        pass

    def enable_trusted_proxy_for_ambari(self):
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
