import sys
import time

from dp_cluster_reg import BColors
from dp_cluster_reg.dataplane import DataPlane
from dp_cluster_reg.config import user
from dp_cluster_reg.cm import ClouderaManager, CMPrerequisites, CMTopologyUtil
from dp_cluster_reg.knox import Knox, KnoxAdminApi, TokenTopology, DpProxyTopologyForCM, DpProxyTopologyForAmbari

from dp_cluster_reg.ambari import Ambari, AmbariPrerequisites, AmbariTopologyUtil


"""
  BaseRegistrationFlow :
"""


class BaseRegistrationFlow(object):

    def __init__(self):
        self.provider = None
        self.dp_instance = None

    def execute(self):
        pass

    def get_dp_instance(self):
        print BColors.BOLD + 'Tell me about your DataPlane Instance' + BColors.ENDC
        return DataPlane(
            user.url_input(
                'DataPlane URL',
                'dp.url'),
            user.credential_input(
                'DP Admin',
                'dp.admin'),
            self.provider)

    def get_roles(self, cluster):
        merged_dependencies = self.dp_instance.dependencies()
        for each in self.dp_instance.optional_dependencies():
            if cluster.cluster_has_service(each.service_name):
                merged_dependencies.add(each)
        role_names = map(lambda each: each.service_name, merged_dependencies)
        return role_names

    def handle_registration_response(self, responses):
        for response in responses:
            # For DP 1.3 the response object contains the code and message
            if 'status' in response and response.get('status') != 200:
                print(
                    '%s Failed! %s%s' %
                    (BColors.FAIL,
                     response.get('message'),
                        BColors.ENDC))
                return 1
            print('Cluster : %s is registered with id : %s ' %
                  (response.get('name'), response.get('id')))
        if responses:
            print BColors.BOLD
            print BColors.OKGREEN
            print(
                "Success! You are all set, your cluster%s is registered and ready to use." %
                ('s' if len(responses) > 1 else ''))
            print BColors.ENDC
        return 0


"""
  AmbariRegistrationFlow : control Operation for ambari based clusters

"""


class AmbariRegistrationFlow(BaseRegistrationFlow):

    def __init__(self):
        self.provider = 'AMBARI'
        self.dp_instance = None

    def execute(self):
        self.dp_instance = self.get_dp_instance()

        dp = self.dp_instance
        print BColors.BOLD + "\nTell me about this cluster's Ambari Instance" + BColors.ENDC
        ambari = Ambari(
            user.url_input(
                'Ambari URL',
                'ambari.url'),
            user.credential_input(
                'Ambari admin',
                'ambari.admin'))
        ambari.enable_trusted_proxy_for_ambari()

        if not AmbariPrerequisites(ambari).satisfied():
            return 1

        if dp.check_dependencies(ambari.cluster, user):
            return 1

        role_names = self.get_roles(ambari)

        topology_util = AmbariTopologyUtil(ambari, role_names)

        knox = Knox(
            user.url_input(
                'Knox URL that is network accessible from DataPlane',
                'knox.url',
                default=str(
                    ambari.cluster.knox_url())),
            knox_user=ambari.cluster.knox_user(),
            knox_group=ambari.cluster.knox_group())

        topologies_to_deploy = [
            TokenTopology(
                dp.public_key()), DpProxyTopologyForAmbari(
                ambari, dp.dependency_names(), topology_util)]

        if 'BEACON' in dp.dependency_names():
            topologies_to_deploy.extend([BeaconProxyTopology(
                ambari, dp.dependency_names(), topology_util)])

        if 'DATA_ANALYTICS_STUDIO' in dp.dependency_names():
            topologies_to_deploy.extend([TokenTopology(
                dp.public_key(), 'redirecttoken', 10000), RedirectTopology('redirect')])
        for topology in topologies_to_deploy:
            print 'Deploying Knox topology:', topology.name
            topology.deploy(knox)

        if 'RANGER' in dp.dependency_names() or dp.optional_dependency_names():
            ambari.enable_trusted_proxy_for_ranger()
        if 'ATLAS' in dp.dependency_names() or dp.optional_dependency_names():
            ambari.enable_trusted_proxy_for_atlas()
        if 'BEACON' in dp.dependency_names() or dp.optional_dependency_names():
            ambari.enable_trusted_proxy_for_beacon()

        print 'Waiting for knox topologies to get activated. Sleeping for 10 seconds...'
        time.sleep(10)
        print 'Cluster changes are complete! Please log into Ambari, confirm the changes made to your cluster as part of this script and restart affected services.'
        user.any_input()

        if not dp.check_ambari(knox):
            return 1

        print 'Registering cluster to DataPlane...'
        response = dp.register_ambari(ambari, knox, user)
        return self.handle_registration_response(response)


"""
  CMRegistrationFlow : control Operation for Clouder Manager based clusters

"""


class CMRegistrationFlow(BaseRegistrationFlow):
    def __init__(self):
        self.provider = 'CM'
        self.dp_instance = None

    def execute(self):

        self.dp_instance = self.get_dp_instance()
        dp = self.dp_instance
        if not dp.version.startswith("1.3"):
            print(
                "Registering CM Based cluster is not supported in DP %s" %
                dp.version)
            return 1
        print BColors.BOLD + "\nTell me about Cloudera Manager Instance" + BColors.ENDC
        cm = ClouderaManager(
            user.url_input(
                'CM URL', 'cm.url'), user.credential_input(
                'CM admin', 'cm.admin'))

        if not CMPrerequisites(cm).satisfied():
            return 1

        #
        # If number of clusters managed by CM = 1 , The script will execute knox based flow
        #
        knox = None
        clusters_to_register = []
        clusters_resp_from_dp = []
        if cm.total_clusters == 1:
            active_cluster = cm.clusters[0]
            knox = KnoxAdminApi(
                user.url_input(
                    'Knox Admin URL', 'knox_admin.url', default=str(
                        active_cluster.knox_url())), user.credential_input(
                    'Knox Admin User', 'knox_admin.user'))
            topology_util = CMTopologyUtil(cm, [])
            topologies_to_deploy = [
                TokenTopology(
                    dp.public_key()), DpProxyTopologyForCM(
                    cm, [], topology_util)]
            for topology in topologies_to_deploy:
                print 'Deploying Knox topology:', topology.name
                topology.deploy(knox)
            # communication check for
            clusters_resp_from_dp = dp.check_cm(cm, knox)
        elif cm.total_clusters > 1:
            clusters_resp_from_dp = dp.check_cm(cm, None)

        if not clusters_resp_from_dp:
            return 1

        clusters_registered = [cluster.get(
            "name") for cluster in clusters_resp_from_dp if not cluster.get("isUnregistered")]
        clusters_not_registered = [cluster.get(
            "name") for cluster in clusters_resp_from_dp if cluster.get("isUnregistered")]

        print BColors.BOLD + \
            "Total clusters managed by Cloudera Manager Instance : %s" % cm.total_clusters + BColors.ENDC
        if cm.total_clusters == 1:
            clusters_to_register = clusters_not_registered
        elif cm.total_clusters > 1:
            print BColors.BOLD + "Clusters already registered in DataPlane : %s" % (
                ','.join([cluster for cluster in clusters_registered]) or 'None') + BColors.ENDC
            print BColors.BOLD + "Clusters which can be registered in DataPlane : %s" % (
                ','.join([cluster for cluster in clusters_not_registered]) or 'None') + BColors.ENDC
            if len(clusters_not_registered) > 0:
                print BColors.UNDERLINE
                print "The user can register all or selective clusters in Dataplane."
                print "For registering selective clusters the user needs to select 'n' and provide a text file containing cluster name/s (one per line) as input"
                print BColors.ENDC
                install_all = user.decision(
                    '%s y/n' %
                    "Register all",
                    "cm.register_all",
                    default=False)
                if install_all:
                    clusters_to_register = clusters_not_registered
                else:
                    user_provided_clusters = []
                    cluster_input_file = user.input(
                        'Enter full path of a file containing names of clusters you would like to register',
                        'cm.cluster_file')
                    with open(cluster_input_file, 'r') as f:
                        for line in f:
                            user_provided_clusters.append(line.strip())
                    clusters_to_register = [
                        cluster for cluster in user_provided_clusters if cluster in clusters_not_registered]
                print BColors.BOLD + "\nClusters which will be registered in DataPlane : %s" % ','.join(
                    [cluster for cluster in clusters_to_register]) + BColors.ENDC

        if clusters_to_register:
            print 'Registering cluster to DataPlane...'
            response = dp.register_cm(cm, knox, user, clusters_to_register)
            if not response:
                return 1
            return self.handle_registration_response(response)
        else:
            print BColors.BOLD + BColors.FAIL + \
                'No valid cluster found to be registered to DataPlane...' + BColors.ENDC
            return 0


"""
  Class for controlling flow of execution
"""


class FlowManager(object):
    def __init__(self, cluster_type):
        self.cluster_type = cluster_type
        self.flow = None

    def initialize(self):
        if self.cluster_type.name in ['HDP', 'HDF']:
            self.flow = AmbariRegistrationFlow()
        if self.cluster_type.name == 'CDH':
            # Check if the required module is present for API to work
            if 'cm_client' not in sys.modules:
                raise ImportError('No module named cm_client')
            self.flow = CMRegistrationFlow()

    def execute(self):
        return self.flow.execute()
