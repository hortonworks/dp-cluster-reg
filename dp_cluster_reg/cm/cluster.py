from dp_cluster_reg.base import BaseCluster
from dp_cluster_reg.rest import Url


class CMCluster(BaseCluster):
    def __init__(self, cluster, client):
        self.client = client
        self.cluster = cluster
        self.cluster_name = cluster.name
        self.version = cluster.full_version
        self.type = 'CDH'
        self.security_type = self._get_cluster_security_type(cluster)

    def _get_cluster_security_type(self, cluster):
        kerb = self.client.cluster_api_instance().get_kerberos_info(self.cluster.name)  # noqa
        security_type = ""
        if kerb.kerberized:
            security_type = "KERBEROS"
        return security_type

    def service(self, service_name):
        data = self.client.services_api_instance().read_service(
            self.cluster_name, service_name)
        return CMService(self.client, data, self.cluster_name)

    def services(self):
        response = self.client.services_api_instance().read_services(
            self.cluster_name, view='summary')
        return [CMService(self.client, data, self.cluster_name)
                for data in response.items]

    def installed_stack(self):
        stack_ver = self.version
        return Stack('CDH', stack_ver, self.client)
    #
    # TODO:
    # currently service name and service types in CM Based cluster differ.
    #

    def service_names(self):
        return [each.type for each in self.services()]

    def add_config(self, config_type, tag, properties, note=''):
        pass

    def update_config(self, config_type, a_dict, note=''):
        pass

    def config(self, config_type):
        pass

    def config_property(self, config_type, property_name, default=None):
        pass

    def knox_url(self):
        return Url.base('https', self.knox_host(), self.knox_port())

    def knox_host(self):
        return self.service('knox').component('KNOX_GATEWAY').host_names()[0]

    def knox_port(self):
        config = filter(lambda c: c.name == 'gateway_port',
                        self.service('knox').component('KNOX_GATEWAY').configs())  # noqa
        if config[0].value:
            return config[0].value
        return config[0].default

    def knox_user(self):
        pass

    def knox_group(self):
        pass

    def cluster_realm(self):
        pass

    def __str__(self):
        return '%s cluster' % self.cluster_name


class CMConfig:
    def __init__(self, a_dict):
        self.name = a_dict.name
        self.value = a_dict.value
        self.default = a_dict.default

    def __str__(self):
        return self.name


class CMServiceComponent:
    def __init__(self, client, a_dict):
        self.client = client
        self.type = a_dict.type
        self.name = a_dict.name
        self.component = a_dict

    def host_names(self):
        host_id = self.component.host_ref.host_id
        host = self.client.host_resource_api().read_host(host_id)
        return [host.hostname]

    def configs(self):
        configs = self.client.roles_api_instance().read_config(
            self.component.service_ref.cluster_name,
            self.component.role_config_group_ref.role_config_group_name,
            self.component.service_ref.service_name,
            view="FULL"
        )
        return [CMConfig(config) for config in configs.items]

    def __str__(self):
        return self.name


class CMService:
    def __init__(self, client, a_dict, cluster_name):
        self.client = client
        self.service = a_dict
        self.cluster_name = cluster_name
        self.name = self.service.name
        self.type = self.service.type
        self.display_name = self.service.display_name

    def components(self):
        roles = self.client.role_resource_instance().read_roles(
            self.cluster_name, self.name, filter="", view='summary')
        return [CMServiceComponent(self.client, role) for role in roles.items]

    def component(self, component_name):
        matches = [each for each in self.components() if each.type ==
                   component_name]
        return matches[0] if matches else None

    def component_type(self, component_type):
        matches = [each for each in self.components() if each.type ==
                   component_type]
        return matches

    def __str__(self):
        return self.name


class Stack:
    def __init__(self, stack_name, stack_version, client):
        self.name = stack_name
        self.version = stack_version
        self.client = client

    def __str__(self):
        return "%s-%s" % (self.name, self.version)
