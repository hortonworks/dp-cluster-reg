import base64
from dp_cluster_reg.base import BaseClusterManager
from dp_cluster_reg.rest import Credentials, RestClient, Header, Url

from .cluster import AmbariCluster, Stack


class Ambari(BaseClusterManager):
    def __init__(
            self,
            base_url,
            credentials=Credentials(
                'admin',
                'admin'),
            api_version='v1'):
        self.base_url = base_url
        self.client = RestClient.forJsonApi(
            self.base_url /
            'api' /
            api_version,
            credentials,
            headers=[
                Header.csrf()])
        self.api_version = api_version
        self.cluster = self._find_cluster()
        self.internal_host = self._find_internal_host_name()

    def _find_cluster(self):
        cluster_name = self._find_cluster_name()
        _, response = self.client.get((Url('clusters') / cluster_name).query_params(  # noqa
            fields='Clusters/security_type,Clusters/version,Clusters/cluster_name'))  # noqa
        return AmbariCluster(
            response['Clusters'],
            self.client.rebased(
                self.base_url /
                'api' /
                self.api_version /
                'clusters' /
                cluster_name))

    def _find_repository_version(self, cluster_name):
        _, response = self.client.get(
            (Url('clusters') / cluster_name / 'stack_versions').query_params(**{'ClusterStackVersions/state': 'CURRENT'}))
        current_stack_version_id = response['items'][0]['ClusterStackVersions']['id']
        current_stack_repository_version = response['items'][0]['ClusterStackVersions']['repository_version']
        _, response = self.client.get((Url('clusters') /
                                       cluster_name /
                                       'stack_versions' /
                                       current_stack_version_id /
                                       'repository_versions' /
                                       current_stack_repository_version).query_params(fields='RepositoryVersions/repository_version'))
        current_repo_version = response['RepositoryVersions']['repository_version']
        print 'Detected current repo version as: %s' % current_repo_version
        return current_repo_version

    def _find_cluster_name(self):
        try:
            _, response = self.client.get('clusters')
            return response['items'][0]['Clusters']['cluster_name']
        except Exception as e:
            raise NoClusterFound(e)

    def _find_internal_host_name(self):
        _, data = self.client.get('services/AMBARI/components/AMBARI_SERVER')
        return data['hostComponents'][0]['RootServiceHostComponents']['host_name']

    def installed_stack(self):
        stack_name, stack_ver = self.cluster.version.split('-')
        return Stack(
            stack_name,
            stack_ver,
            self.client.rebased(
                self.base_url /
                'api' /
                self.api_version /
                'stacks'))

    def current_stack_version(self):
        return self._find_repository_version(self.cluster.cluster_name)

    def cluster_has_service(self, name):
        if not self.cluster.has_service(name):
            return False
        else:
            return True

    def enable_trusted_proxy_for_ranger(self):
        if not self.cluster.has_service('RANGER'):
            return
        print 'Enabling Knox Trusted Proxy Support in Ranger...'
        knox_user = self.cluster.knox_user()
        print '  Please be aware: Adding ranger.proxyuser.%s.users=* to ranger-admin-site' % knox_user  # noqa
        print '  Please be aware: Adding ranger.proxyuser.%s.groups=* to ranger-admin-site' % knox_user  # noqa
        self.cluster.update_config('ranger-admin-site', {
            'ranger.authentication.allow.trustedproxy': 'true',
            'ranger.proxyuser.%s.hosts' % knox_user: self.cluster.knox_host(),
            'ranger.proxyuser.%s.users' % knox_user: '*',
            'ranger.proxyuser.%s.groups' % knox_user: '*',
        }, note='updated by dp-cluster-setup-utility')

    def enable_trusted_proxy_for_atlas(self):
        if not self.cluster.has_service('ATLAS'):
            return
        print 'Enabling Knox Trusted Proxy Support in Atlas...'
        knox_user = self.cluster.knox_user()
        print '  Please be aware: Adding atlas.proxyuser.%s.users=* to application-properties' % knox_user  # noqa
        print '  Please be aware: Adding atlas.proxyuser.%s.users=* to application-properties' % knox_user  # noqa
        self.cluster.update_config('application-properties', {
            'atlas.authentication.method.trustedproxy': 'true',
            'atlas.proxyuser.%s.hosts' % knox_user: self.cluster.knox_host(),
            'atlas.proxyuser.%s.users' % knox_user: '*',
            'atlas.proxyuser.%s.groups' % knox_user: '*',
        }, note='updated by dp-cluster-setup-utility')

    def enable_trusted_proxy_for_beacon(self):
        print 'Enabling Knox Trusted Proxy Support in BEACON...'
        knox_user = self.cluster.knox_user()
        print 'Setting trusted proxy configurations in beacon-security-site'
        self.cluster.update_config('beacon-security-site', {
            'beacon.trustedProxy.enabled': 'true',
            'beacon.trustedProxy.topologyName': 'beacon-proxy',
            'beacon.proxyuser.%s.hosts' % knox_user: self.cluster.knox_host(),
            'beacon.proxyuser.%s.users' % knox_user: '*',
            'beacon.proxyuser.%s.groups' % knox_user: '*',
        }, note='updated by dp-cluster-setup-utility')

    def enable_trusted_proxy_for_ambari_2_6(self):
        print 'Enabling Knox Trusted Proxy Support in Ambari 2.6 '
        ambari_host = self.internal_host
        knox_user = self.cluster.knox_user()
        knox_host = self.cluster.knox_host()
        if ambari_host != knox_host:
            print "Warning: Ambari host and Knox host are not same." \
                  "Please run the ambari-server setup-trusted-proxy in Ambari host as a prerequisite. " \
                  "Use knox as local proxy username, knox host in allowed hosts and default values for others."
        else:
            print "Ambari host and Knox host are same. So running ambari-server setup-trusted-proxy."
            setup_trusted_proxy_command = "printf '\n%s\n%s\n*\n*\n\n' | ambari-server setup-trusted-proxy" % (
                knox_user, knox_host)
            os.system(setup_trusted_proxy_command)

    def enable_trusted_proxy_for_ambari(self):
        knox_user = self.cluster.knox_user()
        stack = self.installed_stack()
        if (stack.version.startswith('2.6')):
            self.enable_trusted_proxy_for_ambari_2_6()
            return
        print 'Enabling Knox Trusted Proxy Support in Ambari 3.1 '
        print '  Please be aware: Adding ambari.tproxy.proxyuser.%s.users=* to tproxy-configuration' % knox_user  # noqa
        print '  Please be aware: Adding ambari.tproxy.proxyuser.%s.users=* to tproxy-configuration' % knox_user  # noqa
        _, response = self.client.post('services/AMBARI/components/AMBARI_SERVER/configurations', {
            'Configuration': {
                'category': 'tproxy-configuration',
                'properties': {
                    'ambari.tproxy.authentication.enabled': 'true',
                    'ambari.tproxy.proxyuser.%s.hosts' % knox_user: self.cluster.knox_host(),  # noqa
                    'ambari.tproxy.proxyuser.%s.users' % knox_user: '*',
                    'ambari.tproxy.proxyuser.%s.groups' % knox_user: '*'
                }
            }
        })
        return response

    def kerberos_enabled(self):
        _, response = self.client.get(
            Url('services/AMBARI/components/AMBARI_SERVER').query_params(
                fields='RootServiceComponents/properties/authentication.kerberos.enabled'))  # noqa
        return 'true' == response \
            .get('RootServiceComponents', {}) \
            .get('properties', {}) \
            .get('authentication.kerberos.enabled', 'false').lower()

    def trusted_proxy_enabled(self):
        _, response = self.client.get(
            Url('services/AMBARI/components/AMBARI_SERVER').query_params(
                fields='RootServiceComponents/properties/ambari.tproxy.authentication.enabled'))  # noqa
        return 'true' == response \
            .get('RootServiceComponents', {}) \
            .get('properties', {}) \
            .get('ambari.tproxy.authentication.enabled', 'false').lower()
