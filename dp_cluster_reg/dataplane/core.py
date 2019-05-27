import sys
from dp_cluster_reg import config, BColors
from .helpers import Dependency
from dp_cluster_reg.rest import RestClient, Header, CookieThief, Credentials

KNOX = Dependency('KNOX', 'Knox')
RANGER = Dependency('RANGER', 'Ranger')
DPPROFILER = Dependency('DPPROFILER', 'Dataplane Profiler')
BEACON = Dependency('BEACON', 'Data Lifecycle Manager (DLM) Engine')
STREAMSMSGMGR = Dependency('STREAMSMSGMGR', 'Streams Messaging Manager')
DATA_ANALYTICS_STUDIO = Dependency(
    'DATA_ANALYTICS_STUDIO',
    'Data Analytics Studio')
ATLAS = Dependency('ATLAS', 'Atlas')
KAFKA = Dependency('KAFKA', 'Kafka')
ZOOKEEPER = Dependency('ZOOKEEPER', 'Zookeeper')
HIVE = Dependency('HIVE', 'Hive')
HDFS = Dependency('HDFS', 'Hdfs')


class DpApp:
    def __init__(self, name, id, dependencies=[], optional_dependencies=[]):
        self.name = name
        self.id = id
        self.dependencies = list(dependencies)
        self.optional_dependencies = list(optional_dependencies)
        self.selected = False


class DataPlane:
    def __init__(self, url, credentials, cluster_provider):
        self.base_url = url
        self.credentials = credentials
        self.client = RestClient.forJsonApi(self.base_url, credentials)
        self.available_apps = self._get_available_apps(cluster_provider)
        self.cluster_provider = cluster_provider
        self.version = self._version()

    def _get_available_apps(self, cluster_provider):
        if cluster_provider == 'CM':
            return [
                DpApp(
                    'Streams Messaging Manager (SMM)',
                    'smm',
                    dependencies=[
                        KNOX,
                        RANGER,
                        STREAMSMSGMGR,
                        KAFKA,
                        ZOOKEEPER]),
            ]
        return [
            DpApp(
                'Data Steward Studio (DSS)', 'dss', dependencies=[
                    KNOX, RANGER, DPPROFILER, ATLAS]),
            DpApp(
                'Data Lifecycle Manager (DLM)', 'dlm', dependencies=[
                    KNOX, RANGER, BEACON, HIVE, HDFS], optional_dependencies=[ATLAS]),
            DpApp(
                'Streams Messaging Manager (SMM)', 'smm', dependencies=[
                    KNOX, RANGER, STREAMSMSGMGR, KAFKA, ZOOKEEPER]),
            DpApp(
                'Data Analytics Studio (DAS)', 'das', dependencies=[
                    KNOX, RANGER, DATA_ANALYTICS_STUDIO, HIVE])]

    def _version(self):
        version_url = self.base_url / 'api' / 'about'
        code, resp = self.client.get(
            version_url, headers=[
                Header.content_type('application/json'), self.token_cookies()])
        if code != 200:
            raise UnexpectedHttpCode(
                'Unexpected HTTP code: %d url: %s response: %s' %
                (code, status_url, resp))
        version = resp['version']
        return version

    def check_dependencies(self, cluster, user):
        print '\nWhich DataPlane applications do you want to use with this cluster?'
        self.select_apps(user)
        print '\nChecking Cluster manager - Ambari/Cloudera Manager and your %s ...' % cluster
        cluster_services = cluster.service_names()
        already_checked = set()
        has_missing = False
        for dp_app in self.selected_apps():
            for dp_dep in dp_app.dependencies:
                if dp_dep not in already_checked:
                    sys.stdout.write('You need %s..' % dp_dep.display_name)
                    sys.stdout.flush()
                    if dp_dep.service_name in cluster_services:
                        print '.. Found'
                    else:
                        print '.. Missing!'
                        print '  To configure this cluster for %s, you need to install %s into the cluster.' % (
                            dp_app.name, dp_dep.display_name)
                        print '  You must do this outside of this DataPlane utility, and re-run the script when completed.'
                        has_missing = True
                already_checked.add(dp_dep)
        return has_missing

    def select_apps(self, user):
        for dp_app in self.available_apps:
            dp_app.selected = user.decision(
                '%s y/n' %
                dp_app.name,
                dp_app.id,
                default=False)

    def selected_apps(self):
        return [each for each in self.available_apps if each.selected]

    def has_selected_app(self, app_name):
        return app_name in [each.name for each in self.selected_apps()]

    def dependencies(self):
        dependencies = set()
        for each in self.selected_apps():
            dependencies.update(each.dependencies)
        return dependencies

    def dependency_names(self):
        return map(lambda each: each.service_name, self.dependencies())

    def optional_dependencies(self):
        optional_dependencies = set()
        for each in self.selected_apps():
            optional_dependencies.update(each.optional_dependencies)
        return optional_dependencies

    def optional_dependency_names(self):
        return map(
            lambda each: each.service_name,
            self.optional_dependencies())

    def public_key(self):
        _, key = self.client.get(
            'public-key', response_transformer=lambda url, code, data: (code, data))
        key = key.strip()
        if key.startswith('-----BEGIN CERTIFICATE-----'):
            key = key[len('-----BEGIN CERTIFICATE-----'):]
        if key.endswith('-----END CERTIFICATE-----'):
            key = key[:-len('-----END CERTIFICATE-----')]
        return key

    def register_ambari(self, ambari, knox, user):
        request_data = None
        request_data = self.registration_request_dp_1_2_x_and_below(
            ambari, knox, user)
        if self.version.startswith("1.3"):
            req_copy = request_data.copy()
            req_copy.update(
                self.additional_request_for_dp_1_3_and_above(
                    ambari, knox))
            # dp 1.3 needs the request object to be array
            request_data = [req_copy]
        _, resp = self.client.post(
            'api/lakes',
            data=request_data,
            headers=[Header.content_type('application/json'), self.token_cookies()]
        )
        if self.version.startswith("1.3"):
            return resp
        return [resp]

    def register_cm(self, cm, knox, user, clusters):
        if not self.version.startswith("1.3"):
            print(
                "Registering CM Based cluster is not supported in DP %s" %
                self.version)
            return []
        _, resp = self.client.post(
            'api/lakes',
            data=self.registration_request_cm(cm, knox, user, clusters),
            headers=[Header.content_type('application/json'), self.token_cookies()]
        )
        return resp

    def registration_request_dp_1_2_x_and_below(self, ambari, knox, user):
        ambari_url_via_knox = str(
            knox.base_url /
            'gateway' /
            'dp-proxy' /
            'ambari')
        knox_url = str(knox.base_url / 'gateway')
        return {
            'dcName': user.input(
                'Data Center Name',
                'reg.dc.name'),
            'ambariUrl': ambari_url_via_knox,
            'location': 6789,
            'isDatalake': self.has_selected_app('Data Steward Studio (DSS)'),
            'name': ambari.cluster.cluster_name,
            'description': user.input(
                'Cluster Descriptions',
                'reg.description'),
            'state': 'TO_SYNC',
            'ambariIpAddress': ambari.base_url.ip_address(),
            'allowUntrusted': True,
            'behindGateway': True,
            'knoxEnabled': True,
            'knoxUrl': knox_url,
            'clusterType': ambari.cluster.type,
            'properties': {
                'tags': []}}

    def additional_request_for_dp_1_3_and_above(self, ambari, knox):
        ambari_url_via_knox = str(
            knox.base_url /
            'gateway' /
            'dp-proxy' /
            'ambari')
        knox_url = str(knox.base_url / 'gateway')
        return {
            'managerUri': ambari_url_via_knox,
            'ambariUrl': ambari_url_via_knox,
            'ambariIpAddress': ambari.base_url.ip_address(),
            'managerAddress': ambari.base_url.ip_address(),
            'managerType': "ambari",
        }

    def registration_request_cm(self, cm, knox, user, cluster_names):

        manager_uri = str(cm.base_url)
        knox_url = ""
        knox_enabled = False
        behind_gateway = False
        if knox:
            manager_uri = str(knox.base_url / 'gateway/dp-proxy/cm-api')
            knox_url = str(knox.base_url / 'gateway')
            knox_enabled = True
            behind_gateway = True
        registration_request = []
        cl_dc_name = user.input('Data Center Name', 'reg.dc.name')
        cl_description = user.input('Cluster Descriptions', 'reg.description')
        print BColors.UNDERLINE
        print(
            "All the clusters will be registered in Datacenter : %s with description : %s " %
            (cl_dc_name, cl_description))
        print("User can modify the details later from Dataplane UI")
        print BColors.ENDC
        for cluster_name in cluster_names:
            cluster_objects = filter(
                lambda c: c.cluster_name == cluster_name, cm.clusters)
            if cluster_objects:
                cluster_obj = cluster_objects[0]
                registration_request.append({
                    'dcName': cl_dc_name,
                    'managerUri': manager_uri,
                    'ambariUrl': '',
                    'ambariIpAddress': '',
                    'location': 6789,
                    'isDatalake': self.has_selected_app('Data Steward Studio (DSS)'),
                    'name': cluster_obj.cluster_name,
                    'description': cl_description,
                    'state': 'TO_SYNC',
                    'managerAddress': cm.base_url.ip_address(),
                    'allowUntrusted': True,
                    'behindGateway': behind_gateway,
                    'knoxEnabled': knox_enabled,
                    'knoxUrl': knox_url,
                    'managerType': "cloudera-manager",
                    'clusterType': cluster_obj.type,
                    'properties': {'tags': []}
                })
        return registration_request

    def tokens(self):
        thief = CookieThief()
        hadoop_jwt_token = thief.steal(
            'dp-hadoop-jwt',
            self.websso_url(),
            self.credentials)
        jwt_token = thief.steal(
            'dp_jwt',
            self.identity_url(),
            Credentials.empty())
        return hadoop_jwt_token, jwt_token

    def token_cookies(self):
        hadoop_jwt_token, jwt_token = self.tokens()
        return Header.cookies(
            {'dp-hadoop-jwt': hadoop_jwt_token, 'dp_jwt': jwt_token})

    def websso_url(self):
        return (
            self.base_url /
            'knox/gateway/knoxsso/api/v1/websso').query_params(
            originalUrl=self.base_url)

    def identity_url(self):
        return self.base_url / 'api' / 'identity'

    def check_ambari(self, knox):
        if self.version.startswith("1.3"):
            return self._check_ambari_for_dp_1_3_and_above(knox)
        return self._check_ambari_for_dp_1_2_x_and_below(knox)

    def _check_ambari_for_dp_1_2_x_and_below(self, knox):
        print 'Checking communication between DataPlane and cluster...'
        status_url = Url('api/ambari/status').query_params(url=knox.base_url /
                                                           'gateway/dp-proxy/ambari', allowUntrusted='true', behindGateway='true')
        code, resp = self.client.get(
            status_url, headers=[
                Header.content_type('application/json'), self.token_cookies()])
        if code != 200:
            raise UnexpectedHttpCode(
                'Unexpected HTTP code: %d url: %s response: %s' %
                (code, status_url, resp))
        status = resp['ambariApiStatus']
        print '  Ambari API status:', status
        if status != 200:
            print 'Communication failure. DataPlane response: %s' % resp
            return False
        return True

    def _check_ambari_for_dp_1_3_and_above(self, knox):
        print 'Checking communication between DataPlane and Ambari...'
        code, resp = self.client.post(
            'api/cluster-managers?action=check',
            data={
                'managerType': 'ambari',
                'managerUri': str(knox.base_url / 'gateway/dp-proxy/ambari'),
                'allowUntrusted': True,
                'withSingleSignOn': False,
                'behindGateway': True
            },
            headers=[Header.content_type('application/json'), self.token_cookies()]
        )
        if len(resp) > 0:
            return True
        return False

    def check_cm(self, cm, knox):
        print 'Checking communication between DataPlane and Cloudera Manager ...'
        manager_uri = str(cm.base_url)
        behind_gateway = False
        if knox:
            manager_uri = str(knox.base_url / 'gateway/dp-proxy/cm-api')
            behind_gateway = False
        code, resp = self.client.post(
            'api/cluster-managers?action=check',
            data={
                'managerType': 'cloudera-manager',
                'managerUri': manager_uri,
                'allowUntrusted': True,
                'withSingleSignOn': False,
                'behindGateway': behind_gateway
            },
            headers=[Header.content_type('application/json'), self.token_cookies()]
        )
        return resp
