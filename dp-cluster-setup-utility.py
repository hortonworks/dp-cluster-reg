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
from contextlib import closing
from urlparse import urlparse

class InputValidator:
  class Any:
    def valid(self, input): return True
    def describe_failure(self, name): return

  class NonBlank:
    def valid(self, input): return len(input.strip()) > 0
    def describe_failure(self, name): print '%s cannot be blank' % name

  class Options:
    def __init__(self, a_set): self.options = a_set
    def valid(self, input): return input in self.options
    def describe_failure(self, _): print 'Invalid option, please choose from: %s' % (', '.join(self.options))

  class YesNo(Options):
    def __init__(self): InputValidator.Options.__init__(self, ('y', 'n'))

  class Url:
    def valid(self, input):
      if not (input.startswith('http://') or input.startswith('https://')):
        return False
      result = urlparse(input)
      return result.scheme and result.netloc

    def describe_failure(self, name):
      print '%s is not a valid URL. Use the following format http(s)://host[:port]' % name

class User:
  @classmethod
  def decision(cls, prompt, default):
    return cls.input(prompt, '', default='y' if default else 'n', validator=InputValidator.YesNo()) == 'y'

  @classmethod
  def input(cls, prompt, description, default="", sensitive=False, validator=InputValidator.NonBlank()):
    input = ""
    prompt = "%s [%s]: " % (prompt, default) if default else prompt + ": "
    while not input:
      input = getpass.getpass(prompt) if sensitive else raw_input(prompt)
      if not input.strip() and default:
        return default
      if validator.valid(input):
        return input
      validator.describe_failure(description)
      input = ""
    return input

  @classmethod
  def any_input(cls, prompt='Press enter to continue'):
    return cls.input(prompt, 'any', validator=InputValidator.Any())

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
  def ask_for(cls, name, default=None):
    return Url(User.input('%s URL' % name, 'URL', validator=InputValidator.Url(), default=default))

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
  def ask_for(name, default_user=None, default_password=None):
    return Credentials(
      User.input('%s username' % name, "Username", default=default_user),
      User.input('%s password' % name, "Password", sensitive=True, default=default_password))

  @staticmethod
  def empty():
    class EmptyCredentials:
      def add_to(self, request): pass
    return EmptyCredentials()

  def __init__(self, user, password):
    self.header = Header(
      'Authorization',
      'Basic %s' % base64.encodestring('%s:%s' % (user, password)).replace('\n', ''))

  def add_to(self, request):
    self.header.add_to(request)

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
               timeout = 120):
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
      return UnexpectedHttpCode('Unexpected http code: %d url: %s response: %s' % (code, url, data))

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

class Ambari:
  def __init__(self, base_url, credentials=Credentials('admin', 'admin'), api_version='v1'):
    self.base_url = base_url
    self.client = RestClient.forJsonApi(self.base_url / 'api' / api_version, credentials, headers=[Header.csrf()])
    self.api_version = api_version
    self.cluster = self._find_cluster()
    self.internal_host = self._find_internal_host_name()

  def _find_cluster(self):
    cluster_name = self._find_cluster_name()
    _, response = self.client.get((Url('clusters') / cluster_name).query_params(fields='Clusters/security_type,Clusters/version,Clusters/cluster_name'))
    return Cluster(response['Clusters'], self.client.rebased(self.base_url / 'api' / self.api_version / 'clusters' / cluster_name))

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

  def enable_trusted_proxy_for_ranger(self):
    if not self.cluster.has_service('RANGER'):
      return
    print 'Enabling Knox Trusted Proxy Support in Ranger...'
    knox_user = self.cluster.knox_user()
    print 'WARNING: Adding ranger.proxyuser.%s.users=* to ranger-admin-site' % knox_user
    print 'WARNING: Adding ranger.proxyuser.%s.groups=* to ranger-admin-site' % knox_user
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
    print 'WARNING: Adding atlas.proxyuser.%s.users=* to atlas-application.properties' % knox_user
    print 'WARNING: Adding atlas.proxyuser.%s.users=* to atlas-application.properties' % knox_user
    self.cluster.update_config('atlas-application.properties', {
      'atlas.authentication.method.trustedproxy' : 'true',
      'atlas.proxyuser.%s.hosts' % knox_user: self.cluster.knox_host(),
      'atlas.proxyuser.%s.users' % knox_user: '*',
      'atlas.proxyuser.%s.groups' % knox_user: '*',
    }, note='updated by dp-cluster-setup-utility')

  def enable_trusted_proxy_for_ambari(self):
    print 'Enabling Knox Trusted Proxy Support in Ambari...'
    knox_user = self.cluster.knox_user()
    print 'WARNING: Adding ambari.tproxy.proxyuser.%s.users=* to tproxy-configuration' % knox_user
    print 'WARNING: Adding ambari.tproxy.proxyuser.%s.users=* to tproxy-configuration' % knox_user
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

class Cluster:
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

  def has_service(self, service_name):
    return service_name in self.service_names()

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
    return Configs(self.client, [Config(self.client, each) for each in data['items']])

  def config_property(self, config_type, property_name, default=None):
    return self.config(config_type).latest().properties().get(property_name, default)

  def knox_host(self):
    return self.service('KNOX').component('KNOX_GATEWAY').host_names()[0]

  def knox_user(self):
    return self.config_property('knox-env', 'knox_user', default='knox')

  def __str__(self):
    return 'Cluster: %s' % self.cluster_name

class NoClusterFound(Exception): pass
class NoConfigFound(Exception): pass

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
  def __init__(self, client, config_list):
    self.client = client
    self.configs = sorted(config_list, key=lambda config: config.version())

  def latest(self):
    if len(self.configs) < 1:
      raise NoConfigFound()
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
  def __init__(self, name, dependencies=[]):
    self.name = name
    self.dependencies = list(dependencies)
    self.selected = False

KNOX = Dependency('KNOX', 'Knox')
RANGER = Dependency('RANGER', 'Ranger')
DPPROFILER = Dependency('DPPROFILER', 'Dataplane Profiler')
BEACON = Dependency('BEACON', 'DLM Engine')
STREAMSMSGMGR = Dependency('STREAMSMSGMGR', 'Streams Messaging Manager')
DATA_ANALYTICS_STUDIO = Dependency('DATA_ANALYTICS_STUDIO', 'Data Analytics Studio')
ATLAS = Dependency('ATLAS', 'Atlas')
KAFKA = Dependency('KAFKA', 'Kafka')
ZOOKEEPER = Dependency('ZOOKEEPER', 'Zookeeper')
HIVE = Dependency('HIVE', 'Hive')
HDFS = Dependency('HDFS', 'Hdfs')

class DataPlain:
  def __init__(self, url, credentials):
    self.base_url = url
    self.credentials = credentials
    self.client = RestClient.forJsonApi(self.base_url, credentials)
    self.available_apps = [
      DpApp('DSS', dependencies=[KNOX, RANGER, DPPROFILER, ATLAS]),
      DpApp('DLM', dependencies=[KNOX, RANGER, BEACON, HIVE, HDFS]),
      DpApp('SMM', dependencies=[KNOX, RANGER, STREAMSMSGMGR, KAFKA, ZOOKEEPER]),
      DpApp('DAS', dependencies=[KNOX, RANGER, DATA_ANALYTICS_STUDIO, HIVE])
    ]

  def check_dependencies(self, cluster):
    print 'Which DataPlane apps you want to use?'
    self.select_apps()
    print 'Checking Ambari and %s...' % cluster
    cluster_services = cluster.service_names()
    already_checked = set()
    has_missing = False
    for dp_app in self.selected_apps():
      for dp_dep in dp_app.dependencies:
        if dp_dep not in already_checked:
          sys.stdout.write('You need %s..' % dp_dep.display_name)
          sys.stdout.flush()
          if dp_dep.service_name in cluster_services:
            print '..check'
          else:
            print '..missing!'
            print '  To configure this cluster for %s, you need to install %s into the cluster.' % (dp_app.name, dp_dep.display_name)
            print '  You must do this outside of this DataPlane utility'
            has_missing = True
        already_checked.add(dp_dep)
    return has_missing

  def select_apps(self):
    for dp_app in self.available_apps:
      dp_app.selected = User.decision('%s y/n' % dp_app.name, default=False)

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

  def public_key(self):
    _, key = self.client.get('public-key', response_transformer=lambda url, code, data: (code, data))
    key = key.strip()
    if key.startswith('-----BEGIN CERTIFICATE-----'):
      key = key[len('-----BEGIN CERTIFICATE-----'):]
    if key.endswith('-----END CERTIFICATE-----'):
      key = key[:-len('-----END CERTIFICATE-----')]
    return key

  def register_ambari(self, ambari, knox):
    _, resp = self.client.post(
      'api/lakes',
      data=self.registration_request(ambari, knox),
      headers=[Header.content_type('application/json'), self.token_cookies()]
    )
    return resp

  def registration_request(self, ambari, knox):
    ambari_url_via_knox = str(knox.base_url / 'gateway' / 'dp-proxy' / 'ambari')
    knox_url = str(knox.base_url / 'gateway')
    return {
      'dcName': User.input('dcName', 'dcName'),
      'ambariUrl': ambari_url_via_knox,
      'location': 12,
      'isDatalake': self.has_selected_app('DSS'),
      'name': ambari.cluster.cluster_name,
      'description': User.input('description', 'description'),
      'state': 'TO_SYNC',
      'ambariIpAddress': ambari.base_url.ip_address(),
      'allowUntrusted': True,
      'behindGateway': True,
      'knoxEnabled': True,
      'knoxUrl': knox_url,
      'clusterType': ambari.cluster.type,
      'properties': {'tags': []}
    }

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
           <value>10000</value>
        </param>
        <param>
           <name>knox.token.client.data</name>
           <value>cookie.name=hadoop-jwt</value>
        </param>
     </service>
  </topology>"""

  def __init__(self, pem, name='token'):
    self.pem = pem
    self.name = name

  def deploy(self, knox):
    template = TokenTopology.TEMPLATE.format(
      knox_url = str(knox.base_url),
      timestamp = int(time.time()),
      pem = self.pem
    )
    return knox.add_topology(self.name, template)

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
        <url>{ambari_protocol}://{ambari_host}:{ambari_port}</url>
     </service>
     {ranger}
     {atlas}
     {atlas_api}
     {dpprofiler}
     {beacon}
     {streamsmsgmgr}
     {das}
  </topology>"""

  def __init__(self, ambari, role_names, name='dp-proxy'):
    self.ambari = ambari
    self.role_names = role_names
    self.name = name

  def deploy(self, knox):
    template = DpProxyTopology.TEMPLATE.format(
      knox_url = str(knox.base_url),
      timestamp = int(time.time()),
      ambari_protocol = self.ambari.base_url.protocol(),
      ambari_host = self.ambari.internal_host,
      ambari_port = self.ambari.base_url.port(),
      ranger = self.ranger(),
      atlas = self.atlas(),
      atlas_api = self.atlas_api(),
      dpprofiler = self.dpprofiler(),
      beacon = self.beacon(),
      streamsmsgmgr = self.streamsmsgmgr(),
      das = self.das()
    )
    return knox.add_topology(self.name, template)

  def ranger(self):
    return self.role('RANGER', self.ranger_url()) if 'RANGER' in self.role_names else ''

  def atlas(self):
    return self.role('ATLAS', self.atlas_url()) if 'ATLAS' in self.role_names else ''

  def atlas_api(self):
    return self.role('ATLAS-API', self.atlas_url()) if 'ATLAS' in self.role_names else ''

  def dpprofiler(self):
    return self.role('DPPROFILER', self.dpprofiler_url()) if 'DPPROFILER' in self.role_names else ''

  def beacon(self):
    return self.role('BEACON', self.beacon_url()) if 'BEACON' in self.role_names else ''

  def streamsmsgmgr(self):
    return self.role('STREAMSMSGMGR', self.streamsmsgmgr_url()) if 'STREAMSMSGMGR' in self.role_names else ''

  def das(self):
    return self.role('DATA_ANALYTICS_STUDIO', self.das_url()) if 'DATA_ANALYTICS_STUDIO' in self.role_names else ''

  def role(self, name, url):
    return """
    <service>
      <role>{role}</role>
      <url>{url}</url>
    </service>""".format(role=name, url=url)

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

  def das_url(self):
    host = self.host_name('DATA_ANALYTICS_STUDIO', 'DATA_ANALYTICS_STUDIO_EVENT_PROCESSOR')
    port = self.ambari.cluster.config_property('data_analytics_studio-event_processor-properties', 'data_analytics_studio_event_processor_admin_server_port')
    proto = self.ambari.cluster.config_property('data_analytics_studio-event_processor-properties', 'data_analytics_studio_event_processor_server_protocol')
    return '%s://%s:%s' % (proto, host, port)

  def host_name(self, service_name, component_name):
    return self.ambari.cluster.service(service_name).component(component_name).host_names()[0]

class Knox:
  def __init__(self, url, credentials, api_version="v1", gateway_path='gateway'):
    self.base_url = url
    self.client = RestClient.forJsonApi(self.base_url / gateway_path / 'admin' / 'api' / api_version, credentials)
    self.client.default_headers.append(Header.accept_json())
    self.gateway_path = gateway_path

  def topologies(self):
    _, response = self.client.get(Url('topologies'))
    return response

  def topology(self, topology_name):
    _, response = self.client.get(Url('topologies') / topology_name)
    return response

  def add_topology(self, topology_name, content):
    _, response = self.client.put(
      Url("topologies") / topology_name,
      data=content,
      request_transformer=lambda any:any,
      headers=[Header.content_type('application/xml')])
    return response

class AmbariPrerequisites:
  def __init__(self, ambari):
    self.ambari = ambari

  def satisfied(self):
    if not self.stack_supported():
      print 'Your stack (%s) is not supported. Supported stacks are: HDP-3.1 or newer.' % self.ambari.installed_stack()
      return False
    if not self.security_type_supported():
      print 'Your cluster is not kerberied. Please enable Kerberos in Ambari first.'
      return False
    if not ambari.kerberos_enabled():
      print 'Kerberos is not enabled for Ambari. Please enable it by running: ambari-server setup-kerberos.'
      return False
    return True

  def stack_supported(self):
    stack = self.ambari.installed_stack()
    return stack.name == 'HDP' and stack.version.startswith('3.1')

  def security_type_supported(self):
    return self.ambari.cluster.security_type == 'KERBEROS'

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

if __name__ == '__main__':
  print 'Tell me about your DataPlane Instance'
  dp = DataPlain(Url.ask_for('DataPlane'), Credentials.ask_for('DP Admin'))

  print 'Tell me about your Ambari'
  ambari = Ambari(Url.ask_for('Ambari'), Credentials.ask_for('Ambari admin'))

  if not AmbariPrerequisites(ambari).satisfied():
    sys.exit(1)
  if dp.check_dependencies(ambari.cluster):
    sys.exit(1)

  knox = Knox(
    Url.ask_for('Knox'),
    Credentials.ask_for('Knox Admin'),
    gateway_path=ambari.cluster.config_property('gateway-site', 'gateway.path', default='gateway'))

  for topology in [TokenTopology(dp.public_key()), DpProxyTopology(ambari, dp.dependency_names())]:
    print 'Deploying Knox topology:', topology.name
    topology.deploy(knox)

  if 'RANGER' in dp.dependency_names():
    ambari.enable_trusted_proxy_for_ranger()
  if 'ATLAS' in dp.dependency_names():
    ambari.enable_trusted_proxy_for_atlas()
  ambari.enable_trusted_proxy_for_ambari()

  print 'Done. You need to go into Ambari, confirm the changes and do restarts.'
  User.any_input()

  print 'Registering cluster to DataPlane...'
  response = dp.register_ambari(ambari, knox)
  print 'Cluster is registered with id', response['id']

  print 'Success! You are all done, your cluster is registered and ready to use'
