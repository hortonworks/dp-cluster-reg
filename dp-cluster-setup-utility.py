"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import base64
import getpass
import json
import socket
import ssl
import sys
import time
import urllib2
import os
import pwd
import grp
import warnings
from contextlib import closing
from urlparse import urlparse
from shutil import copyfile
import pprint
pp = pprint.PrettyPrinter(indent=4)


try:
    import cm_client
    from cm_client.rest import ApiException
except ImportError:
    warnings.warn('cm_client failed to import', ImportWarning)


class InputValidator:
  class Any:
    def valid(self, _): return True
    def describe_failure(self): return

  class NonBlank:
    def valid(self, input): return len(input.strip()) > 0
    def describe_failure(self): print 'Input cannot be blank'

  class Options:
    def __init__(self, a_set): self.options = a_set
    def valid(self, input): return input in self.options
    def describe_failure(self): print 'Invalid option, please choose from: %s' % (', '.join(self.options))

  class YesNo(Options):
    def __init__(self): InputValidator.Options.__init__(self, ('y', 'n'))
  class ClusterType(Options):
    def __init__(self): InputValidator.Options.__init__(self, ('HDP', 'HDF', 'CDH')) 
  class Url:
    def valid(self, input):
      if not (input.startswith('http://') or input.startswith('https://')):
        return False
      result = urlparse(input)
      return result.scheme and result.netloc

    def describe_failure(self):
      print 'The entered URL is invalid. Use the following format http(s)://host[:port]'

class ClusterType:
  def __init__(self, name):
    self.name = name
  def __str__(self):
    return self.name

class User:
  def decision(self, prompt, name, default):
    return self.input(prompt, name, default='y' if default else 'n', validator=InputValidator.YesNo()) == 'y'

  def input(self, prompt, id, default="", sensitive=False, validator=InputValidator.NonBlank()):
    input = ""
    prompt = "%s [%s]: " % (prompt, default) if default else prompt + ": "
    while not input:
      input = getpass.getpass(prompt) if sensitive else raw_input(prompt)
      if not input.strip() and default:
        return default
      if validator.valid(input):
        return input
      validator.describe_failure()
      input = ""
    return input

  def url_input(self, name, id, default=None):
    return Url(self.input('%s (http(s)://host:[port])' % name, id, validator=InputValidator.Url(), default=default))

  def credential_input(self, name, id, default_user=None, default_password=None):
    return Credentials(
      self.input('%s username' % name, id, default=default_user),
      self.input('%s password' % name, id, sensitive=True, default=default_password))
  def cluster_type_input(self, name, id, default_cluster_type=None):
    return ClusterType(
      self.input('%s [HDP/HDF/CDH]' % name, id, validator=InputValidator.ClusterType(), default=default_cluster_type))
  def any_input(self, prompt='Press enter to continue'):
    return self.input(prompt, 'any', validator=InputValidator.Any())

class Memorized:
  def __init__(self, user, file_name='dp-cluster-setup-utility.history'):
    self.user = user
    self.file_name = file_name
    self.history = self._load()

  def decision(self, prompt, id, default):
    answer = self.user.decision(prompt, id, self._get(id, default))
    self._update({id: answer})
    return answer

  def input(self, prompt, id, default="", sensitive=False, validator=InputValidator.NonBlank()):
    answer = self.user.input(prompt, id, default=self._get(id, default), sensitive=sensitive, validator=validator)
    if not sensitive:
      self._update({id: answer})
    return answer

  def url_input(self, name, id, default=None):
    answer = self.user.url_input(name, id, default=self._get(id, default))
    self._update({id: str(answer)})
    return answer

  def credential_input(self, name, id, default_user=None, default_password=None):
    key = "%s.user" % id
    answer = self.user.credential_input(name, id, default_user=self._get(key, default_user), default_password=default_password)
    self._update({key: answer.user})
    return answer
  def cluster_type_input(self, name, id, default_cluster_type=None):
    answer = self.user.cluster_type_input(name, id, default_cluster_type=self._get(id, default_cluster_type))
    self._update({id: answer.name})
    return answer
  def any_input(self, prompt='Press enter to continue'):
    return self.user.any_input(prompt)

  def _load(self):
    try:
      with open(self.file_name, 'r') as f: return json.load(f)
    except Exception:
      return {}

  def _update(self, update):
    self.history.update(update)
    with open(self.file_name, 'w') as f:
      json.dump(self.history, f, indent=2)

  def _get(self, name, default):
    return self.history.get(name, "") or default

class SslContext:
  def build(self):
    if not hasattr(ssl, 'SSLContext'):
      return None
    return ssl.SSLContext(self._protocol()) if self._protocol() else ssl.create_default_context()

  def _protocol(self):
    if hasattr(ssl, 'PROTOCOL_TLS'): return ssl.PROTOCOL_TLS
    elif hasattr(ssl, 'PROTOCOL_TLSv1_2'): return ssl.PROTOCOL_TLSv1_2
    elif hasattr(ssl, 'PROTOCOL_TLSv1_1'): return ssl.PROTOCOL_TLSv1_1
    elif hasattr(ssl, 'PROTOCOL_TLSv1'): return ssl.PROTOCOL_TLSv1
    else: return None

class PermissiveSslContext:
  def build(self):
    context = SslContext().build()
    if hasattr(context, '_https_verify_certificates'):
      context._https_verify_certificates(False)
    if (hasattr(context, 'verify_mode')):
      context.check_hostname = False
      context.verify_mode = ssl.CERT_NONE
    return context

class Url:
  @classmethod
  def base(cls, protocol, host, port):
    return cls('%s://%s:%s' % (protocol, host, port))

  def __init__(self, url_str):
    self.base = url_str.rstrip('/')

  def __div__(self, suffix_url):
    suffix_str = str(suffix_url)
    if self._is_absolute(suffix_str):
      return Url(suffix_str)
    else:
      return Url(self.base + (suffix_str if suffix_str.startswith('/') else '/' + suffix_str))

  def _is_absolute(self, suffix_str):
    return suffix_str.startswith(self.base)

  def query_params(self, **params):
    return Url(self.base + '?' + '&'.join('%s=%s' % (name, value) for name, value in params.items()))

  def netloc(self):
    return urlparse(self.base).netloc

  def protocol(self, default='http'):
    scheme = urlparse(self.base).scheme
    return scheme if scheme else default

  def ip_address(self):
    if self.netloc():
      return socket.gethostbyname(self.netloc().split(':')[0])
    else:
      return None # might be relative URL

  def port(self, default=80):
    netloc = self.netloc()
    return int(netloc.split(':')[1]) if ':' in netloc else default

  def __str__(self):
    return self.base

class Header:
  @classmethod
  def csrf(cls):
    return cls('X-Requested-By', 'ambari')

  @classmethod
  def accept(cls, content_types):
    return cls('Accept', ', '.join(content_types))

  @classmethod
  def accept_json(cls):
    return cls.accept(['application/json'])

  @classmethod
  def content_type(cls, content_type):
    return cls('Content-Type', content_type)

  @classmethod
  def cookies(cls, a_dict):
    return cls('Cookie', '; '.join('='.join(each) for each in a_dict.items()))

  def __init__(self, key, value):
    self.key, self.value = key, value

  def add_to(self, request):
    request.add_header(self.key, self.value)

class Credentials:
  @staticmethod
  def empty():
    class EmptyCredentials:
      def add_to(self, request): pass
    return EmptyCredentials()

  def __init__(self, user, password):
    self.user = user
    self.password = password
    self.header = Header(
      'Authorization',
      'Basic %s' % base64.encodestring('%s:%s' % (user, password)).replace('\n', ''))

  def add_to(self, request):
    self.header.add_to(request)

class CMRestClient:
  def __init__(self,url,credentials):
    self.url = url
    self.credentials = credentials
    self.client = self._get_basic_client(url, credentials)
  
  def _get_basic_client(self, api_url, cred):
    cm_client.configuration.username = cred.user
    cm_client.configuration.password = cred.password
    return cm_client.ApiClient(str(api_url))

  def cluster_api_instance(self):
    return cm_client.ClustersResourceApi(self.client)
  
  def services_api_instance(self):
    return cm_client.ServicesResourceApi(self.client)
  
  def cm_api_instance(self):
    return cm_client.ClouderaManagerResourceApi(self.client)
  
  def roles_api_instance(self):
    return cm_client.RoleConfigGroupsResourceApi(self.client)
  
  def role_resource_instance(self):
    return cm_client.RolesResourceApi(self.client)

  def all_host_resource_instance(self): 
    return cm_client.AllHostsResourceApi(self.client)

  def parcels_resource_api(self):
    return cm_client.ParcelsResourceApi(self.client)

class RestClient:
  @classmethod
  def forJsonApi(cls, url, credentials, headers=[], ssl_context=PermissiveSslContext()):
    return cls(
      url,
      credentials,
      headers=headers,
      ssl_context=ssl_context,
      request_transformer=json.dumps,
      response_transformer=JsonTransformer())

  def __init__(self,
               an_url,
               credentials,
               headers=[],
               ssl_context=SslContext(),
               request_transformer=lambda r:r,
               response_transformer=lambda url, code, data: (code, data),
               timeout = 60):
    self.base_url = an_url
    self.credentials = credentials
    self.default_headers = headers
    self.ssl_context = ssl_context
    self.request_transformer = request_transformer
    self.response_transformer = response_transformer
    self.timeout = timeout

  def get(self, suffix_str, response_transformer=None, headers=[]):
    request, ssl_context = self._request(suffix_str, 'GET', self.request_transformer, headers=headers)
    return self._response(request, ssl_context, response_transformer or self.response_transformer)

  def delete(self, suffix_str, response_transformer=None, headers=[]):
    request, ssl_context = self._request(suffix_str, 'DELETE', self.request_transformer, headers=headers)
    return self._response(request, ssl_context, response_transformer or self.response_transformer)

  def post(self, suffix_str, data, request_transformer=None, response_transformer=None, headers=[]):
    request, ssl_context = self._request(suffix_str, 'POST', request_transformer or self.request_transformer, data=data, headers=headers)
    return self._response(request, ssl_context, response_transformer or self.response_transformer)

  def put(self, suffix_str, data, request_transformer=None, response_transformer=None, headers=[]):
    request, ssl_context = self._request(suffix_str, 'PUT', request_transformer or self.request_transformer, data=data, headers=headers)
    return self._response(request, ssl_context, response_transformer or self.response_transformer)

  def _request(self, suffix_str, http_method, request_transformer, data="", headers=[]):
    url = str(self.base_url / suffix_str)
    request = urllib2.Request(url, data=request_transformer(data))
    request.get_method = lambda: http_method
    for each in [self.credentials] + self.default_headers + headers:
      each.add_to(request)
    return request, self.ssl_context.build()

  def _response(self, request, ssl_context, response_transformer):
    try:
      with closing(urllib2.urlopen(request, context=ssl_context, timeout=self.timeout)) as response:
        return response_transformer(request.get_full_url(), response.getcode(), response.read())
    except urllib2.HTTPError as e:
      print '* Error while requesting URL: %s' % request.get_full_url()
      print '* Error message: %s' % e.read()
      raise e
    except urllib2.URLError as e:
      print '* Error while requesting URL: %s' % request.get_full_url()
      raise e

  def rebased(self, new_base_url, request_transformer=None, response_transformer=None):
    return RestClient(
      new_base_url,
      self.credentials,
      self.default_headers,
      self.ssl_context,
      request_transformer if request_transformer else self.request_transformer,
      response_transformer if response_transformer else self.response_transformer)

class UnexpectedHttpCode(Exception): pass

class JsonTransformer:
  def __call__(self, url, code, data):
    if 200 <= code <= 299:
      return code, self._parse(data)
    else:
      raise UnexpectedHttpCode('Unexpected HTTP code: %d url: %s response: %s' % (code, url, data))

  def _parse(self, a_str):
    if not a_str: 
      return {}
    try:
      return json.loads(a_str)
    except ValueError as e:
      raise ValueError('Error %s while parsing: %s' % (e, a_str))

class ServiceComponent:
  def __init__(self, client, a_dict):
    self.client = client
    self.name = a_dict['ServiceComponentInfo']['component_name']
    self.component = a_dict

  def host_names(self):
    return [each['HostRoles']['host_name'] for each in self.component['host_components']]

  def __str__(self):
    return self.name
class CMServiceComponent:
  def __init__(self, client, a_dict):
    self.client = client
    self.type = a_dict.type
    self.name = a_dict.name
    self.component = a_dict

  def host_names(self):
    return [each.hostname for each in self.component.host_ref]

  def __str__(self):
    return self.name


class Service:
  def __init__(self, client, a_dict):
    self.client = client
    self.service = a_dict
    self.href = self.service['href']
    self.name = self.service['ServiceInfo']['service_name']

  def components(self):
    return [ServiceComponent(self.client, self.client.get(each['href'])[1]) for each in self.service['components']]

  def component(self, component_name):
    matches = [each for each in self.components() if each.name == component_name]
    return matches[0] if matches else None

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
    roles = self.client.role_resource_instance().read_roles(self.cluster_name, self.name,filter="filter",view='summary')
    return [CMServiceComponent(self.client, role) for role in roles.items]

  def component(self, component_name):
    matches = [each for each in self.components() if each.name == component_name]
    return matches[0] if matches else None

  def component_type(self, component_type):
    matches = [each for each in self.components() if each.type == component_type]
    return matches

  def __str__(self):
    return self.name



class BaseClusterManager(object):
  """ Base class for  cluster """
  def installed_stack(self):
    pass
  def current_stack_version(self):
    pass
  def enable_trusted_proxy_for_ranger(self):
    pass
  def enable_trusted_proxy_for_atlas(self):
    pass
  def enable_trusted_proxy_for_beacon(self):
    pass
  def enable_trusted_proxy_for_cluster_manager(self):
    pass
  def kerberos_enabled(self):
    pass

class Ambari(BaseClusterManager):
  def __init__(self, base_url, credentials=Credentials('admin', 'admin'), api_version='v1'):
    self.base_url = base_url
    self.client = RestClient.forJsonApi(self.base_url / 'api' / api_version, credentials, headers=[Header.csrf()])
    self.api_version = api_version
    self.cluster = self._find_cluster()
    self.internal_host = self._find_internal_host_name()

  def _find_cluster(self):
    cluster_name = self._find_cluster_name()
    _, response = self.client.get((Url('clusters') / cluster_name).query_params(fields='Clusters/security_type,Clusters/version,Clusters/cluster_name'))
    return AmbariCluster(response['Clusters'], self.client.rebased(self.base_url / 'api' / self.api_version / 'clusters' / cluster_name))

  def _find_repository_version(self, cluster_name):
    _, response = self.client.get((Url('clusters') / cluster_name / 'stack_versions').query_params(**{'ClusterStackVersions/state':'CURRENT'}))
    current_stack_version_id = response['items'][0]['ClusterStackVersions']['id']
    current_stack_repository_version = response['items'][0]['ClusterStackVersions']['repository_version']
    _, response = self.client.get((Url('clusters') / cluster_name / 'stack_versions' / current_stack_version_id / 'repository_versions' / current_stack_repository_version).query_params(fields='RepositoryVersions/repository_version'))
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
    return Stack(stack_name, stack_ver, self.client.rebased(self.base_url / 'api' / self.api_version / 'stacks'))

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
    print '  Please be aware: Adding ranger.proxyuser.%s.users=* to ranger-admin-site' % knox_user
    print '  Please be aware: Adding ranger.proxyuser.%s.groups=* to ranger-admin-site' % knox_user
    self.cluster.update_config('ranger-admin-site', {
      'ranger.authentication.allow.trustedproxy' : 'true',
      'ranger.proxyuser.%s.hosts' % knox_user: self.cluster.knox_host(),
      'ranger.proxyuser.%s.users' % knox_user: '*',
      'ranger.proxyuser.%s.groups' % knox_user: '*',
    }, note='updated by dp-cluster-setup-utility')

  def enable_trusted_proxy_for_atlas(self):
    if not self.cluster.has_service('ATLAS'):
      return
    print 'Enabling Knox Trusted Proxy Support in Atlas...'
    knox_user = self.cluster.knox_user()
    print '  Please be aware: Adding atlas.proxyuser.%s.users=* to application-properties' % knox_user
    print '  Please be aware: Adding atlas.proxyuser.%s.users=* to application-properties' % knox_user
    self.cluster.update_config('application-properties', {
      'atlas.authentication.method.trustedproxy' : 'true',
      'atlas.proxyuser.%s.hosts' % knox_user: self.cluster.knox_host(),
      'atlas.proxyuser.%s.users' % knox_user: '*',
      'atlas.proxyuser.%s.groups' % knox_user: '*',
    }, note='updated by dp-cluster-setup-utility')

  def enable_trusted_proxy_for_beacon(self):
    print 'Enabling Knox Trusted Proxy Support in BEACON...'
    knox_user = self.cluster.knox_user()
    print 'Setting trusted proxy configurations in beacon-security-site'
    self.cluster.update_config('beacon-security-site', {
      'beacon.trustedProxy.enabled' : 'true',
      'beacon.trustedProxy.topologyName' : 'beacon-proxy',
      'beacon.proxyuser.%s.hosts' % knox_user: self.cluster.knox_host(),
      'beacon.proxyuser.%s.users' % knox_user: '*',
      'beacon.proxyuser.%s.groups' % knox_user: '*',
    }, note='updated by dp-cluster-setup-utility')


  def enable_trusted_proxy_for_ambari_2_6(self):
    print 'Enabling Knox Trusted Proxy Support in Ambari 2.6 '
    ambari_host = self.internal_host
    knox_user = self.cluster.knox_user()
    knox_host = self.cluster.knox_host()
    if ambari_host != knox_host :
      print "Warning: Ambari host and Knox host are not same." \
            "Please run the ambari-server setup-trusted-proxy in Ambari host as a prerequisite. " \
            "Use knox as local proxy username, knox host in allowed hosts and default values for others."
    else :
      print "Ambari host and Knox host are same. So running ambari-server setup-trusted-proxy."
      setup_trusted_proxy_command = "printf '\n%s\n%s\n*\n*\n\n' | ambari-server setup-trusted-proxy" %(knox_user, knox_host)
      os.system(setup_trusted_proxy_command)

  def enable_trusted_proxy_for_ambari(self):
    knox_user = self.cluster.knox_user()
    stack = self.installed_stack()
    if (stack.version.startswith('2.6')) :
      self.enable_trusted_proxy_for_ambari_2_6()
      return
    print 'Enabling Knox Trusted Proxy Support in Ambari 3.1 '
    print '  Please be aware: Adding ambari.tproxy.proxyuser.%s.users=* to tproxy-configuration' % knox_user
    print '  Please be aware: Adding ambari.tproxy.proxyuser.%s.users=* to tproxy-configuration' % knox_user
    _, response = self.client.post('services/AMBARI/components/AMBARI_SERVER/configurations', {
      'Configuration': {
        'category' : 'tproxy-configuration',
        'properties': {
          'ambari.tproxy.authentication.enabled': 'true',
          'ambari.tproxy.proxyuser.%s.hosts' % knox_user:  self.cluster.knox_host(),
          'ambari.tproxy.proxyuser.%s.users' % knox_user:  '*',
          'ambari.tproxy.proxyuser.%s.groups' % knox_user: '*'
        }
      }
    })
    return response

  def kerberos_enabled(self):
    _, response = self.client.get(Url('services/AMBARI/components/AMBARI_SERVER').query_params(
      fields='RootServiceComponents/properties/authentication.kerberos.enabled'
    ))
    return 'true' == response \
             .get('RootServiceComponents', {}) \
             .get('properties', {}) \
             .get('authentication.kerberos.enabled', 'false').lower()


  def trusted_proxy_enabled(self):
    _, response = self.client.get(Url('services/AMBARI/components/AMBARI_SERVER').query_params(
      fields='RootServiceComponents/properties/ambari.tproxy.authentication.enabled'
    ))
    return 'true' == response \
    .get('RootServiceComponents', {}) \
    .get('properties', {}) \
    .get('ambari.tproxy.authentication.enabled', 'false').lower()

class ClouderaManager(BaseClusterManager):
  """ Base class for  cluster """
  def __init__(self, base_url, credentials=Credentials('admin', 'admin'), api_version='v19'):
    self.base_url = base_url
    self.client = CMRestClient(base_url / 'api' / api_version, credentials)
    self.api_version = api_version
    self.clusters = self._find_clusters_detail()
    self.total_clusters = self._total_clusters()
    self.internal_host = self._find_internal_host_name()

  def _find_clusters_detail(self):
    clusters = self._find_clusters()
    return [CMCluster(cluster,self.client) for cluster in clusters]
  
  def _find_repository_version(self, cluster_name):
    pass

  def _total_clusters(self):
    return len(self.clusters) if self.clusters else 0

  def _find_clusters(self):
    try:
      response = self.client.cluster_api_instance().read_clusters(view='full')
      return response.items
    except ApiException as e:
      raise NoClusterFound(e)

  def get_cluster_instance(self, cluster_name):
    for cluster in self.clusters:
      if cluster.name == cluster_name:
        return cluster
    return None
  
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
    pass


class BaseCluster(object):

  def has_service(self, service_name):
    return service_name in self.service_names()
  
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
    return [Service(self.client, self.client.get(each['href'])[1]) for each in data['items']]

  def service_names(self):
    return [each.name for each in self.services()]

  def add_config(self, config_type, tag, properties, note=''):
    self.client.post(Url('configurations'), {
      'type': config_type,
      'tag': str(tag),
      'properties' : properties
    })
    self.client.put('', {
      'Clusters' : { 
        'desired_configs': {'type': config_type, 'tag' : str(tag), 'service_config_version_note': note }
      }
    })

  def update_config(self, config_type, a_dict, note=''):
    properties = self.config(config_type).latest().properties()
    properties.update(a_dict)
    self.add_config(config_type, Tag.random(config_type), properties, note)

  def config(self, config_type):
    code, data = self.client.get(Url('configurations').query_params(type=config_type))
    return Configs(self.client, [Config(self.client, each) for each in data['items']], config_type)

  def config_property(self, config_type, property_name, default=None):
    return self.config(config_type).latest().properties().get(property_name, default)

  def knox_url(self):
    return Url.base('https', self.knox_host(), self.knox_port())

  def knox_host(self):
    return self.service('KNOX').component('KNOX_GATEWAY').host_names()[0]

  def knox_port(self):
    return int(self.config_property('gateway-site', 'gateway.port', default='8443'))

  def knox_user(self):
    return self.config_property('knox-env', 'knox_user', default='knox')

  def knox_group(self):
    return self.config_property('knox-env', 'knox_group', default='knox')
  
  def cluster_realm(self):
    return self.config_property('kerberos-env', 'realm')

  def __str__(self):
    return '%s cluster' % self.cluster_name

class NoClusterFound(Exception): pass
class NoConfigFound(Exception): pass

class CMCluster(BaseCluster):
  def __init__(self, cluster, client):
    self.client = client
    self.cluster = cluster
    self.cluster_name = cluster.name
    self.version = cluster.full_version
    self.type = 'CDH'
    self.security_type = self._get_cluster_security_type(cluster)

  def _get_cluster_security_type(self,cluster):
    kerb = self.client.cluster_api_instance().get_kerberos_info(self.cluster.name)
    security_type = ""
    if kerb.kerberized :
      security_type = "KERBEROS"
    return security_type

  def service(self, service_name):
    try:
      data = self.client.services_api_instance().read_service(self.cluster_name, service_name)
      return Service(self.client, data)
    except ApiException as e:
      raise e

  def services(self):
    try:
      response = self.client.services_api_instance().read_services(self.cluster_name, view='summary')
      return [CMService(self.client, data, self.cluster_name) for data in response.items]
    except ApiException as e:
      raise e

  def installed_stack(self):
    stack_ver = self.version
    return Stack('CDH', stack_ver, self.client)
  #
  # TODO: currently service name and service types in CM BAsed cluster differ.
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
    pass

  def knox_host(self):
    pass

  def knox_port(self):
    pass

  def knox_user(self):
    pass

  def knox_group(self):
    pass
  
  def cluster_realm(self):
    pass

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

class Stack:
  def __init__(self, stack_name, stack_version, client):
    self.name = stack_name
    self.version = stack_version
    self.client = client

  def __str__(self):
    return "%s-%s" % (self.name, self.version)

class Tag:
  @classmethod
  def random(self, name): return self("%s-%s" % (name, time.time()))
  def __init__(self, name): self.name = name
  def __str__(self): return self.name

class Dependency:
  def __init__(self, service_name, display_name):
    self.service_name = service_name
    self.display_name = display_name

  def __eq__(self, that): return isinstance(that, type(self)) and self.service_name == that.service_name
  def __hash__(self): return hash(self.service_name)

class DpApp:
  def __init__(self, name, id, dependencies=[], optional_dependencies=[]):
    self.name = name
    self.id = id
    self.dependencies = list(dependencies)
    self.optional_dependencies = list(optional_dependencies)
    self.selected = False

KNOX = Dependency('KNOX', 'Knox')
RANGER = Dependency('RANGER', 'Ranger')
DPPROFILER = Dependency('DPPROFILER', 'Dataplane Profiler')
BEACON = Dependency('BEACON', 'Data Lifecycle Manager (DLM) Engine')
STREAMSMSGMGR = Dependency('STREAMSMSGMGR', 'Streams Messaging Manager')
DATA_ANALYTICS_STUDIO = Dependency('DATA_ANALYTICS_STUDIO', 'Data Analytics Studio')
ATLAS = Dependency('ATLAS', 'Atlas')
KAFKA = Dependency('KAFKA', 'Kafka')
ZOOKEEPER = Dependency('ZOOKEEPER', 'Zookeeper')
HIVE = Dependency('HIVE', 'Hive')
HDFS = Dependency('HDFS', 'Hdfs')

class DataPlane:
  def __init__(self, url, credentials, cluster_provider):
    self.base_url = url
    self.credentials = credentials
    self.client = RestClient.forJsonApi(self.base_url, credentials)
    self.available_apps = self._get_available_apps(cluster_provider)
    self.cluster_provider = cluster_provider
    self.version = self._version()
  
  def _get_available_apps(self,cluster_provider):
    if cluster_provider == 'CM':
      return [
      DpApp('Streams Messaging Manager (SMM)', 'smm', dependencies=[KNOX, RANGER, STREAMSMSGMGR, KAFKA, ZOOKEEPER]),
    ]
    return [
      DpApp('Data Steward Studio (DSS)', 'dss', dependencies=[KNOX, RANGER, DPPROFILER, ATLAS]),
      DpApp('Data Lifecycle Manager (DLM)', 'dlm', dependencies=[KNOX, RANGER, BEACON, HIVE, HDFS], optional_dependencies=[ATLAS]),
      DpApp('Streams Messaging Manager (SMM)', 'smm', dependencies=[KNOX, RANGER, STREAMSMSGMGR, KAFKA, ZOOKEEPER]),
      DpApp('Data Analytics Studio (DAS)', 'das', dependencies=[KNOX, RANGER, DATA_ANALYTICS_STUDIO, HIVE])
    ]

  def _version(self):
    version_url = self.base_url / 'api' / 'about'
    code, resp = self.client.get(version_url, headers=[Header.content_type('application/json'), self.token_cookies()])
    if code != 200:
      raise UnexpectedHttpCode('Unexpected HTTP code: %d url: %s response: %s' % (code, status_url, resp))
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
            print '  To configure this cluster for %s, you need to install %s into the cluster.' % (dp_app.name, dp_dep.display_name)
            print '  You must do this outside of this DataPlane utility, and re-run the script when completed.'
            has_missing = True
        already_checked.add(dp_dep)
    return has_missing

  def select_apps(self, user):
    for dp_app in self.available_apps:
      dp_app.selected = user.decision('%s y/n' % dp_app.name, dp_app.id, default=False)

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
      return map(lambda each: each.service_name, self.optional_dependencies())

  def public_key(self):
    _, key = self.client.get('public-key', response_transformer=lambda url, code, data: (code, data))
    key = key.strip()
    if key.startswith('-----BEGIN CERTIFICATE-----'):
      key = key[len('-----BEGIN CERTIFICATE-----'):]
    if key.endswith('-----END CERTIFICATE-----'):
      key = key[:-len('-----END CERTIFICATE-----')]
    return key

  def register_ambari(self, ambari, knox, user):
    request_data = None
    request_data = self.registration_request_dp_1_2_x_and_below(ambari, knox, user)
    if self.version.startswith("1.3"):
      req_copy = request_data.copy()
      req_copy.update(self.additional_request_for_dp_1_3_and_above(ambari,knox))
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
  
  def register_cm(self, cm, user, clusters):
    if not self.version.startswith("1.3"):
      print("Registering CM Based cluster is not supported in DP %s" % self.version)
      return []
    _, resp = self.client.post(
      'api/lakes',
      data=self.registration_request_cm(cm, user, clusters),
      headers=[Header.content_type('application/json'), self.token_cookies()]
    )
    return resp
  
  def registration_request_dp_1_2_x_and_below(self, ambari, knox, user):
    ambari_url_via_knox = str(knox.base_url / 'gateway' / 'dp-proxy' / 'ambari')
    knox_url = str(knox.base_url / 'gateway')
    return {
      'dcName': user.input('Data Center Name', 'reg.dc.name'),
      'ambariUrl': ambari_url_via_knox,
      'location': 6789,
      'isDatalake': self.has_selected_app('Data Steward Studio (DSS)'),
      'name': ambari.cluster.cluster_name,
      'description': user.input('Cluster Descriptions', 'reg.description'),
      'state': 'TO_SYNC',
      'ambariIpAddress': ambari.base_url.ip_address(),
      'allowUntrusted': True,
      'behindGateway': True,
      'knoxEnabled': True,
      'knoxUrl': knox_url,
      'clusterType': ambari.cluster.type,
      'properties': {'tags': []}
    }
  
  def additional_request_for_dp_1_3_and_above(self,ambari, knox):
    ambari_url_via_knox = str(knox.base_url / 'gateway' / 'dp-proxy' / 'ambari')
    knox_url = str(knox.base_url / 'gateway')
    return {
      'managerUri': ambari_url_via_knox,
      'ambariUrl': ambari_url_via_knox,
      'ambariIpAddress': ambari.base_url.ip_address(),
      'managerAddress': ambari.base_url.ip_address(),
      'managerType': "ambari",
    }

  def registration_request_cm(self, cm, user, cluster_names):
    registration_request = []
    for cluster_name in cluster_names:
      cluster_obj = next(obj for obj in cm.clusters if obj.cluster_name == cluster_name)
      print("Enter details for cluster : %s" % cluster_name)
      registration_request.append({
        'dcName': user.input('Data Center Name', 'reg.dc.name'),
        'managerUri': str(cm.base_url),
        'ambariUrl': '',
        'ambariIpAddress': '',
        'location': 6789,
        'isDatalake': self.has_selected_app('Data Steward Studio (DSS)'),
        'name': cluster_obj.cluster_name,
        'description': user.input('Cluster Descriptions', 'reg.description'),
        'state': 'TO_SYNC',
        'managerAddress': cm.base_url.ip_address(),
        'allowUntrusted': True,
        'behindGateway': False,
        'knoxEnabled': False,
        'managerType': "cloudera-manager",
        'clusterType': cluster_obj.type,
        'properties': {'tags': []}
      })
    return registration_request

  def tokens(self):
    thief = CookieThief()
    hadoop_jwt_token = thief.steal('dp-hadoop-jwt', self.websso_url(), self.credentials)
    jwt_token = thief.steal('dp_jwt', self.identity_url(), Credentials.empty())
    return hadoop_jwt_token, jwt_token

  def token_cookies(self):
    hadoop_jwt_token, jwt_token = self.tokens()
    return Header.cookies({'dp-hadoop-jwt': hadoop_jwt_token, 'dp_jwt': jwt_token})

  def websso_url(self):
    return (self.base_url / 'knox/gateway/knoxsso/api/v1/websso').query_params(originalUrl=self.base_url)

  def identity_url(self):
    return self.base_url / 'api' / 'identity'
  
  def check_ambari(self,knox):
    if self.version.startswith("1.3"):
      return self._check_ambari_for_dp_1_3_and_above(knox)
    return self._check_ambari_for_dp_1_2_x_and_below(knox)
  
  def _check_ambari_for_dp_1_2_x_and_below(self, knox):
    print 'Checking communication between DataPlane and cluster...'
    status_url = Url('api/ambari/status').query_params(url=knox.base_url / 'gateway/dp-proxy/ambari', allowUntrusted='true', behindGateway='true')
    code, resp = self.client.get(status_url, headers=[Header.content_type('application/json'), self.token_cookies()])
    if code != 200:
      raise UnexpectedHttpCode('Unexpected HTTP code: %d url: %s response: %s' % (code, status_url, resp))
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

  def check_cm(self, cm):
    print 'Checking communication between DataPlane and Cloudera Manager ...'
    code, resp = self.client.post(
      'api/cluster-managers?action=check',
      data={
	        'managerType': 'cloudera-manager',
        	'managerUri': str(cm.base_url),
	        'allowUntrusted': False,
	        'withSingleSignOn': False,
	        'behindGateway': False
      },
      headers=[Header.content_type('application/json'), self.token_cookies()]
    )
    return resp


class TokenTopology:
  TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
  <topology>
     <uri>{knox_url}/gateway/token</uri>
     <name>token</name>
     <timestamp>{timestamp}</timestamp>
     <generated>false</generated>
     <gateway>
        <provider>
           <role>federation</role>
           <name>SSOCookieProvider</name>
           <enabled>true</enabled>
           <param>
              <name>sso.authentication.provider.url</name>
              <value>{knox_url}/gateway/knoxsso/api/v1/websso</value>
           </param>
           <param>
              <name>sso.token.verification.pem</name>
              <value>{pem}</value>
           </param>
        </provider>
        <provider>
           <role>identity-assertion</role>
           <name>HadoopGroupProvider</name>
           <enabled>true</enabled>
        </provider>
     </gateway>
     <service>
        <role>KNOXTOKEN</role>
        <param>
           <name>knox.token.ttl</name>
           <value>{token_ttl}</value>
        </param>
        <param>
           <name>knox.token.client.data</name>
           <value>cookie.name=hadoop-jwt</value>
        </param>
     </service>
  </topology>"""

  def __init__(self, pem, name='token', token_ttl=100000):
    self.pem = pem
    self.name = name
    self.token_ttl = token_ttl

  def deploy(self, knox):
    template = TokenTopology.TEMPLATE.format(
      knox_url = str(knox.base_url),
      timestamp = int(time.time()),
      pem = self.pem,
      token_ttl = self.token_ttl
    )
    return knox.add_topology(self.name, template)

class TopologyUtil:
  def __init__(self, ambari, role_names):
    self.ambari = ambari
    self.role_names = role_names

  def ranger(self):
    return self.role('RANGER', self.ranger_url(), '0.1.0.0') if 'RANGER' in self.role_names else ''

  def atlas_api(self):
    return self.role('ATLAS-API', self.atlas_url(), '0.1.2.0') if 'ATLAS' in self.role_names else ''

  def dpprofiler(self):
    return self.role('PROFILER-AGENT', self.dpprofiler_url()) if 'DPPROFILER' in self.role_names else ''

  def beacon(self):
    return self.role('BEACON', self.beacon_url()) if 'BEACON' in self.role_names else ''

  def streamsmsgmgr(self):
    return self.role('SMM', self.streamsmsgmgr_url()) if 'STREAMSMSGMGR' in self.role_names else ''

  def role(self, name, url, version=''):
    version_str = ''
    if version:
      version_str = '<version>{version}</version>'.format(version=version)
    return """
    <service>
      <role>{role}</role>
      {version_str}
      <url>{url}</url>
    </service>""".format(role=name, url=url, version_str=version_str)

class AmbariTopologyUtil(TopologyUtil):
  def __init__(self, ambari, role_names):
    self.ambari = ambari
    self.role_names = role_names
  def ranger_url(self):
    host = self.host_name('RANGER', 'RANGER_ADMIN')
    if self.ambari.cluster.config_property('ranger-admin-site', 'ranger.service.https.attrib.ssl.enabled') == 'true':
      port = self.ambari.cluster.config_property('ranger-admin-site', 'ranger.service.https.port')
      return 'https://%s:%s' % (host, port)
    else:
      port = self.ambari.cluster.config_property('ranger-admin-site', 'ranger.service.http.port')
      return 'http://%s:%s' % (host, port)

  def atlas_url(self):
    host = self.host_name('ATLAS', 'ATLAS_SERVER')
    if self.ambari.cluster.config_property('application-properties', 'atlas.enableTLS') == 'true':
      port = self.ambari.cluster.config_property('application-properties', 'atlas.server.https.port')
      return 'https://%s:%s' % (host, port)
    else:
      port = self.ambari.cluster.config_property('application-properties', 'atlas.server.http.port')
      return 'http://%s:%s' % (host, port)

  def dpprofiler_url(self):
    host = self.host_name('DPPROFILER', 'DP_PROFILER_AGENT')
    port = self.ambari.cluster.config_property('dpprofiler-env', 'dpprofiler.http.port')
    return 'http://%s:%s' % (host, port)

  def beacon_url(self):
    host = self.host_name('BEACON', 'BEACON_SERVER')
    if self.ambari.cluster.config_property('beacon-env', 'beacon_tls_enabled') == 'true':
      port = self.ambari.cluster.config_property('beacon-env', 'beacon_tls_port')
      return 'https://%s:%s' % (host, port)
    else:
      port = self.ambari.cluster.config_property('beacon-env', 'beacon_port')
      return 'http://%s:%s' % (host, port)

  def streamsmsgmgr_url(self):
    host = self.host_name('STREAMSMSGMGR', 'STREAMSMSGMGR')
    if self.ambari.cluster.config_property('streams-messaging-manager-ssl-config', 'streams_messaging_manager.ssl.isenabled') == 'true':
      port = self.ambari.cluster.config_property('streams-messaging-manager-common', 'streams_messaging_manager.ssl.port')
      return 'https://%s:%s' % (host, port)
    else:
      port = self.ambari.cluster.config_property('streams-messaging-manager-common', 'port')
      return 'http://%s:%s' % (host, port)

  def host_name(self, service_name, component_name):
    return self.ambari.cluster.service(service_name).component(component_name).host_names()[0]

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



class DpProxyTopology:
  TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
  <topology>
     <uri>{knox_url}/gateway/dp-proxy</uri>
     <name>dp-proxy</name>
     <timestamp>{timestamp}</timestamp>
     <generated>false</generated>
     <gateway>
        <provider>
           <role>federation</role>
           <name>SSOCookieProvider</name>
           <enabled>true</enabled>
           <param>
              <name>sso.authentication.provider.url</name>
              <value>{knox_url}/gateway/knoxsso/api/v1/websso</value>
           </param>
        </provider>
        <provider>
           <role>identity-assertion</role>
           <name>Default</name>
           <enabled>true</enabled>
        </provider>
     </gateway>
     <service>
        <role>AMBARI</role>
        <version>0.2.2.0</version>
        <url>{ambari_protocol}://{ambari_host}:{ambari_port}</url>
     </service>
     {ranger}
     {atlas_api}
     {dpprofiler}
     {beacon}
     {streamsmsgmgr}
  </topology>"""

  def __init__(self, ambari, role_names, topology_util, name='dp-proxy'):
    self.ambari = ambari
    self.role_names = role_names
    self.name = name
    self.topology_util = topology_util

  def deploy(self, knox):
    self.update_knox_service_defs(knox)
    template = DpProxyTopology.TEMPLATE.format(
      knox_url = str(knox.base_url),
      timestamp = int(time.time()),
      ambari_protocol = self.ambari.base_url.protocol(),
      ambari_host = self.ambari.internal_host,
      ambari_port = self.ambari.base_url.port(),
      ranger = self.topology_util.ranger(),
      atlas_api = self.topology_util.atlas_api(),
      dpprofiler = self.topology_util.dpprofiler(),
      beacon = self.topology_util.beacon(),
      streamsmsgmgr = self.topology_util.streamsmsgmgr(),
    )
    return knox.add_topology(self.name, template)

  def update_knox_service_defs(self, knox):
    stack = self.ambari.installed_stack()
    if 'DPPROFILER' in self.role_names:
      if stack.name == 'HDP':
        stack_version = self.ambari.current_stack_version()
        knox.update_profiler_agent_service_def(stack_version)
    if stack.name == 'HDF':
      stack_version = self.ambari.current_stack_version()
      knox.update_ambari_service_def(stack_version)


class BeaconProxyTopology:
  TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
  <topology>
     <uri>{knox_url}/gateway/beacon-proxy</uri>
     <name>beacon-proxy</name>
     <timestamp>{timestamp}</timestamp>
     <generated>false</generated>
     <gateway>
        <provider>
          <role>authentication</role>
          <name>HadoopAuth</name>
          <enabled>true</enabled>
          <param>
            <name>config.prefix</name>
            <value>hadoop.auth.config</value>
          </param>
          <param>
            <name>hadoop.auth.config.signature.secret</name>
            <value>knox-signature-secret</value>
          </param>
          <param>
            <name>hadoop.auth.config.type</name>
            <value>kerberos</value>
          </param>
          <param>
            <name>hadoop.auth.config.simple.anonymous.allowed</name>
            <value>false</value>
          </param>
          <param>
            <name>hadoop.auth.config.token.validity</name>
            <value>1800</value>
          </param>
          <param>
            <name>hadoop.auth.config.cookie.domain</name>
            <value>{realm}</value>
          </param>
          <param>
            <name>hadoop.auth.config.cookie.path</name>
            <value>gateway/beacon-proxy</value>
          </param>
          <param>
            <name>hadoop.auth.config.kerberos.principal</name>
            <value>HTTP/{knox_host}@{realm}</value>
          </param>
          <param>
            <name>hadoop.auth.config.kerberos.keytab</name>
            <value>/etc/security/keytabs/spnego.service.keytab</value>
          </param>
          <param>
            <name>hadoop.auth.config.kerberos.name.rules</name>
            <value>DEFAULT</value>
          </param>
        </provider>
	    <provider>
            <role>identity-assertion</role>
            <name>Default</name>
            <enabled>true</enabled>
        </provider>
     </gateway>
     {ranger}
     {atlas_api}
     {beacon}
  </topology>"""

  def __init__(self, ambari, role_names, topology_util, name='beacon-proxy'):
    self.ambari = ambari
    self.role_names = role_names
    self.name = name
    self.topology_util = topology_util

  def deploy(self, knox):
    template = BeaconProxyTopology.TEMPLATE.format(
      knox_url = str(knox.base_url),
      knox_host = self.ambari.cluster.knox_host(),
      realm = self.ambari.cluster.cluster_realm(),
      timestamp = int(time.time()),
      ranger = self.topology_util.ranger(),
      atlas_api = self.topology_util.atlas_api(),
      beacon = self.topology_util.beacon(),
    )
    return knox.add_topology(self.name, template)

class RedirectTopology:
  TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
  <topology>
    <name>tokensso</name>
    <gateway>
        <provider>
            <role>federation</role>
            <name>JWTProvider</name>
            <enabled>true</enabled>
        </provider>
        <provider>
            <role>identity-assertion</role>
            <name>Default</name>
            <enabled>true</enabled>
        </provider>
    </gateway>
    <service>
        <role>KNOXSSO</role>
        <param>
            <name>knoxsso.cookie.secure.only</name>
            <value>true</value>
        </param>
        <param>
            <name>knoxsso.token.ttl</name>
            <value>600000</value>
        </param>
        <param>
            <name>knoxsso.redirect.whitelist.regex</name>
            <value>^https?:\/\/.*$</value>
        </param>
    </service>
  </topology>"""

  def __init__(self, name='redirect'):
    self.name = name

  def deploy(self, knox):
    print ' Please be aware: Adding a wildcard as the value for knoxsso.redirect.whitelist.regex in %s topology. You can edit this topology file to set a more restrictive value.' % self.name
    return knox.add_topology(self.name, RedirectTopology.TEMPLATE)

class Knox:
  def __init__(self, base_url, knox_user, knox_group, topology_directory='/etc/knox/conf/topologies'):
    self.base_url = base_url
    self.knox_user = knox_user
    self.knox_group = knox_group
    self.topology_directory = self._check_dir(topology_directory)

  def _check_dir(self, knox_artifact_directory, artifact_type='topology'):
    if not os.path.isdir(knox_artifact_directory):
      raise RuntimeError('Knox %s directory does not exist: %s' % (artifact_type, knox_artifact_directory))
    return knox_artifact_directory

  def _check_file(self, service_file):
    if not os.path.isfile(service_file):
      raise RuntimeError('Knox service file does not exist: %s' % service_file)
    return service_file

  def _chown_to_knox(self, path_name):
    os.chown(path_name, pwd.getpwnam(self.knox_user).pw_uid, grp.getgrnam(self.knox_group).gr_gid)

  def add_topology(self, topology_name, content):
    target = '%s/%s.xml' % (self.topology_directory, topology_name)
    print 'Saving topology %s' % target
    with open(target, 'w') as f: f.write(content)
    print '  Changing ownership of %s to %s:%s.' % (topology_name, self.knox_user, self.knox_group)
    self._chown_to_knox(target)
    print '  Changing permissions of %s to %o.' % (topology_name, 0644)
    os.chmod(target, 0644)

  def _create_service_file(self, service, version, file_name, service_dir):
    dest_file = '%s/%s' % (service_dir, file_name)
    src_file = self._check_file('%s/services/%s/%s/%s' % (os.path.dirname(os.path.realpath(__file__)), service, version, file_name))
    copyfile(src_file, dest_file)
    self._chown_to_knox(dest_file)

  def update_profiler_agent_service_def(self, current_stack_version):
    dest_services_base_dir = self._check_dir('/var/lib/knox/data-%s/services' % current_stack_version, 'service')
    service_dir = '%s/profiler-agent/1.0.0' % dest_services_base_dir
    self._execute_service_conf_file_copy_task("profiler-agent", "1.0.0", service_dir)
  
  def update_ambari_service_def(self, current_stack_version):
    dest_services_base_dir = self._check_dir('/var/lib/knox/data-%s/services' % current_stack_version, 'service')
    service_dir = '%s/ambari/0.2.2.0' % dest_services_base_dir
    self._execute_service_conf_file_copy_task("ambari", "0.2.2.0", service_dir)
    
  def _execute_service_conf_file_copy_task(self, service, version, service_dir):
    if os.path.isdir(service_dir):
      print 'Service files already exist in %s' % service_dir
    else:
      os.makedirs(service_dir)

    self._create_service_file(service, version, 'rewrite.xml', service_dir)
    self._create_service_file(service, version, 'service.xml', service_dir)

    self._chown_to_knox(service_dir)
    self._chown_to_knox(os.path.dirname(service_dir))

class BasePrerequisites(object):

  def running_on_knox_host(self):
    if self.knox_host in (socket.gethostname(), socket.getfqdn()):
      return True
    if self.knox_ip() == socket.gethostbyname(socket.gethostname()):
      return True
    hostname, aliases, ips = socket.gethostbyname_ex(socket.gethostname())
    if self.knox_host == hostname or self.knox_host in aliases or self.knox_ip() in ips:
      return True
    return False

  def knox_ip(self):
    try:
      return socket.gethostbyname(self.knox_host)
    except Exception:
      return None

class AmbariPrerequisites(BasePrerequisites):
  def __init__(self, ambari):
    self.ambari = ambari
    self.knox_host = ambari.cluster.knox_host()

  def satisfied(self):
    if not self.stack_supported():
      print 'The stack version (%s) is not supported. Supported stacks are: HDP-2.6/HDP-3.1/HDF-3.3 or newer.' % self.ambari.installed_stack()
      return False
    if not self.security_type_supported():
      print 'Your cluster is not kerberied. Please enable Kerberos using Ambari first.'
      return False
    if not self.ambari.kerberos_enabled():
      print 'Kerberos is not enabled for Ambari. Please enable it by running: ambari-server setup-kerberos from your Ambari Server host.'
      return False
    if self.ambari.installed_stack().version.startswith('2.6') and not ambari.trusted_proxy_enabled():
      print 'Trusted Proxy is not enabled for Ambari. Please enable it by running: ambari-server setup-trusted-proxy from your Ambari Server host.'
      return False
    if not self.running_on_knox_host():
      print 'This script should be executed on the same host where Knox gateway is running (%s).' % self.knox_host
      return False
    return True

  def stack_supported(self):
    return self.hdp_supported_version() or self.hdf_supported_version()

  def hdp_supported_version(self):
    stack = self.ambari.installed_stack()
    return stack.name == 'HDP' and ( stack.version.startswith('3.1') or stack.version.startswith('2.6') )
  
  def hdf_supported_version(self):
    stack = self.ambari.installed_stack()
    return stack.name == 'HDF' and stack.version.startswith('3.3')

  def security_type_supported(self):
    return self.ambari.cluster.security_type == 'KERBEROS'


class CMPrerequisites(BasePrerequisites):
  def __init__(self, cm):
    self.cm = cm

  def satisfied(self):
    for  cluster in self.cm.clusters:
      if not self.stack_supported(cluster):
        print('The stack version (%s) is not supported for %s. Supported stacks are: CDH-5.17/CDH-6.3 or newer.' % (cluster.installed_stack(), cluster.cluster_name))
        return False
    return True

  def stack_supported(self, cluster):
    stack = cluster.installed_stack()
    check_version = False
    (major,minor) = stack.version.split('.')[:2]
    if (major == '5' and int(minor) >= 17) or (major == '6' and int(minor) >= 3):
      check_version = True
    return stack.name == 'CDH' and check_version

  def security_type_supported(self):
    pass


class CookieThief:
  def __init__(self):
    self.cookie_proc = urllib2.HTTPCookieProcessor()
    self.opener = urllib2.build_opener(urllib2.HTTPSHandler(context=self._ssl_context()), self.cookie_proc)

  def _ssl_context(self):
    return PermissiveSslContext().build()

  def steal(self, cookie_name, url, credentials):
    request = urllib2.Request(str(url))
    credentials.add_to(request)
    with closing(self.opener.open(request)) as _:
      for cookie in self.cookie_proc.cookiejar:
        if cookie.name == cookie_name:
          return cookie.value
    return

class ScriptPrerequisites:
  def satisfied(self):
    if 'root' != self.current_user():
      print 'This script should be executed with the root user.'
      return False
    return True

  def current_user(self):
    return pwd.getpwuid(os.getuid()).pw_name
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
    print 'Tell me about your DataPlane Instance'
    return DataPlane(user.url_input('DataPlane URL', 'dp.url'), user.credential_input('DP Admin', 'dp.admin'),self.provider)

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
      if 'status' in response and response.get('status') != 200 :
        print('Failed! %s' % response.get('message'))
        return 1
      print('Cluster : %s is registered with id : %s '% (response.get('name'), response.get('id')))
    if response:
      print('Success! You are all set, your cluster is registered and ready to use.')
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
    print "\nTell me about this cluster's Ambari Instance"
    ambari = Ambari(user.url_input('Ambari URL', 'ambari.url'), user.credential_input('Ambari admin', 'ambari.admin'))
    ambari.enable_trusted_proxy_for_ambari()

    if not AmbariPrerequisites(ambari).satisfied():
      return 1
    
    if dp.check_dependencies(ambari.cluster, user):
      return 1

    role_names = self.get_roles(ambari)

    topology_util = AmbariTopologyUtil(ambari, role_names)

    knox = Knox(user.url_input('Knox URL that is network accessible from DataPlane', 'knox.url', default=str(ambari.cluster.knox_url())), knox_user=ambari.cluster.knox_user(), knox_group=ambari.cluster.knox_group())

    topologies_to_deploy = [TokenTopology(dp.public_key()), DpProxyTopology(ambari, dp.dependency_names(), topology_util)]

    if 'BEACON' in dp.dependency_names():
        topologies_to_deploy.extend([BeaconProxyTopology(ambari, dp.dependency_names(), topology_util)])

    if 'DATA_ANALYTICS_STUDIO' in dp.dependency_names():
      topologies_to_deploy.extend([TokenTopology(dp.public_key(), 'redirecttoken', 10000), RedirectTopology('redirect')])
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
      print("Registering CM Based cluster is not supported in DP %s" % dp.version)
      return 1
    print "\nTell me about Cloudera Manager Instance"
    cm = ClouderaManager(user.url_input('CM URL', 'cm.url'), user.credential_input('CM admin', 'cm.admin'))

    if not CMPrerequisites(cm).satisfied():
      return 1
    
    clusters_resp_from_dp = dp.check_cm(cm)

    if not clusters_resp_from_dp:
      return 1
    
    clusters_registered = [cluster.get("name") for cluster in clusters_resp_from_dp if not cluster.get("isUnregistered")]
    clusters_not_registered = [cluster.get("name") for cluster in clusters_resp_from_dp if cluster.get("isUnregistered")]
    clusters_to_register = []

    print "Total clusters managed by Cloudera Manager Instance : %s" % cm.total_clusters
    if cm.total_clusters == 1:
      clusters_to_register = clusters_not_registered
    elif cm.total_clusters > 1:
      print "Clusters already registered in DataPlane : %s" % ','.join([cluster for cluster in clusters_registered])
      print "Clusters which can be registered in DataPlane : %s" % ','.join([cluster for cluster in clusters_not_registered])
      if len(clusters_not_registered) > 0:
        install_all = user.decision('%s y/n' % "Register all", "cm.register_all", default=False)
        if install_all:
          clusters_to_register = clusters_not_registered
        else:
          user_provided_clusters = []
          cluster_input_file = user.input('Enter full path of file containing cluster names ', 'cm.cluster_file')
          with open(cluster_input_file, 'r') as f:
            for line in f:
              user_provided_clusters.append(line.strip())
          clusters_to_register = [ cluster for cluster in user_provided_clusters if cluster in clusters_not_registered]
        print "\nClusters which will be registered in DataPlane : %s" % ','.join([cluster for cluster in clusters_to_register])
    
    if clusters_to_register:
      print 'Registering cluster to DataPlane...'
      response = dp.register_cm(cm, user, clusters_to_register)
      if not response:
        return 1
      return self.handle_registration_response(response)
    else:
      print 'No valid cluster found to be registered to DataPlane...'
      return 0
    

"""
  Execution Starts here
"""  
if __name__ == '__main__':
  user = Memorized(User())
  print '\nThis script will check to ensure that all necessary pre-requisites have been met and then register this cluster with DataPlane.'
  print '\nThis script works with Cluster manager - Ambari or Cloudera Manager.'
  print '\nIf you are Working with HDP/HDF Clusters managed by Ambari : '
  print '\nPlease ensure that your cluster has kerberos enabled, Ambari has been configured to use kerberos for authentication, and Knox is installed. Once those steps have been done, run this script from the Knox host and follow the steps and prompts to complete the cluster registration process.\n'
  print '\nIf you are Working with CDH clusters managed by Cloudera Manager :'
  print '\nPlease ensure you are running from one of the hosts of the cluster\n'

  # if not ScriptPrerequisites().satisfied():
  #   sys.exit(1)
  # Get the cluster type and execute the flow
  print('Tell me about your Cluster type')
  flow_manager = FlowManager(user.cluster_type_input('Cluster Type ','cluster.type'))
  flow_manager.initialize()
  exit_code = flow_manager.execute()
  sys.exit(exit_code)
