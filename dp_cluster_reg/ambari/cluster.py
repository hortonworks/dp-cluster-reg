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

import json

from dp_cluster_reg.base import BaseCluster
from dp_cluster_reg.rest import Url
from dp_cluster_reg.dataplane import Tag
from dp_cluster_reg.exceptions import NoConfigFound


class AmbariCluster(BaseCluster):
    def __init__(self, cluster, client):
        self.cluster = cluster
        self.cluster_name = cluster['cluster_name']
        self.version = cluster['version']
        self.type = self.version.split('-')[0]
        self.security_type = cluster['security_type']
        self.client = client

    def service(self, service_name):
        _, data = self.client.get(Url('services') / service_name)
        return Service(self.client, data)

    def services(self):
        _, data = self.client.get(Url('services'))
        return [Service(self.client, self.client.get(each['href'])[1])
                for each in data['items']]

    def service_names(self):
        return [each.name for each in self.services()]
    
    def has_service(self, service_name):
        return service_name in self.service_names()

    def add_config(self, config_type, tag, properties, note=''):
        self.client.post(Url('configurations'), {
            'type': config_type,
            'tag': str(tag),
            'properties': properties
        })
        self.client.put(
            '', {
                'Clusters': {
                    'desired_configs': {
                        'type': config_type,
                        'tag': str(tag),
                        'service_config_version_note': note}}})

    def update_config(self, config_type, a_dict, note=''):
        properties = self.config(config_type).latest().properties()
        properties.update(a_dict)
        self.add_config(config_type, Tag.random(config_type), properties, note)

    def config(self, config_type):
        code, data = self.client.get(
            Url('configurations').query_params(
                type=config_type))
        return Configs(self.client, [Config(self.client, each)
                                     for each in data['items']], config_type)

    def config_property(self, config_type, property_name, default=None):
        return self.config(config_type).latest(
        ).properties().get(property_name, default)

    def knox_url(self):
        return Url.base('https', self.knox_host(), self.knox_port())

    def knox_host(self):
        return self.service('KNOX').component('KNOX_GATEWAY').host_names()[0]

    def knox_port(self):
        return int(
            self.config_property(
                'gateway-site',
                'gateway.port',
                default='8443'))

    def knox_user(self):
        return self.config_property('knox-env', 'knox_user', default='knox')

    def knox_group(self):
        return self.config_property('knox-env', 'knox_group', default='knox')

    def cluster_realm(self):
        return self.config_property('kerberos-env', 'realm')

    def __str__(self):
        return '%s cluster' % self.cluster_name


class Config:
    def __init__(self, client, a_dict):
        self.client = client
        self.config = a_dict

    def version(self):
        return int(self.config['version'])

    def href(self):
        return self.config['href']

    def properties(self):
        code, data = self.client.get(self.href())
        return data['items'][0]['properties']

    def __str__(self):
        return json.dumps(self.config)


class Configs:
    def __init__(self, client, config_list, config_type):
        self.client = client
        self.configs = sorted(config_list, key=lambda config: config.version())
        self.config_type = config_type

    def latest(self):
        if len(self.configs) < 1:
            raise NoConfigFound(self.config_type)
        return self.configs[-1]


class ServiceComponent:
    def __init__(self, client, a_dict):
        self.client = client
        self.name = a_dict['ServiceComponentInfo']['component_name']
        self.component = a_dict

    def host_names(self):
        return [each['HostRoles']['host_name']
                for each in self.component['host_components']]

    def __str__(self):
        return self.name


class Service:
    def __init__(self, client, a_dict):
        self.client = client
        self.service = a_dict
        self.href = self.service['href']
        self.name = self.service['ServiceInfo']['service_name']

    def components(self):
        return [ServiceComponent(self.client, self.client.get(each['href'])[
                                 1]) for each in self.service['components']]

    def component(self, component_name):
        matches = [each for each in self.components() if each.name ==
                   component_name]
        return matches[0] if matches else None

    def __str__(self):
        return self.name


class Stack:
    def __init__(self, stack_name, stack_version, client):
        self.name = stack_name
        self.version = stack_version
        self.client = client

    def __str__(self):
        return "%s-%s" % (self.name, self.version)
