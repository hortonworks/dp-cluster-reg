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
from contextlib import closing
from urlparse import urlparse

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

  class Url:
    def valid(self, input):
      if not (input.startswith('http://') or input.startswith('https://')):
        return False
      result = urlparse(input)
      return result.scheme and result.netloc

    def describe_failure(self):
      print 'The entered URL is invalid. Use the following format http(s)://host[:port]'

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
      return UnexpectedHttpCode('Unexpected HTTP code: %d url: %s response: %s' % (code, url, data))

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

  def enable_trusted_proxy_for_ambari(self):
    print 'Enabling Knox Trusted Proxy Support in Ambari...'
    knox_user = self.cluster.knox_user()
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

  def __str__(self):
    return '%s cluster' % self.cluster_name

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
  def __init__(self, name, id, dependencies=[]):
    self.name = name
    self.id = id
    self.dependencies = list(dependencies)
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

class DataPlain:
  def __init__(self, url, credentials):
    self.base_url = url
    self.credentials = credentials
    self.client = RestClient.forJsonApi(self.base_url, credentials)
    self.available_apps = [
      DpApp('Data Steward Studio (DSS)', 'dss', dependencies=[KNOX, RANGER, DPPROFILER, ATLAS]),
      DpApp('Data Lifecycle Manager (DLM)', 'dlm', dependencies=[KNOX, RANGER, BEACON, HIVE, HDFS]),
      DpApp('Streams Messaging Manager (SMM)', 'smm', dependencies=[KNOX, RANGER, STREAMSMSGMGR, KAFKA, ZOOKEEPER]),
      DpApp('Data Analytics Studio (DAS)', 'das', dependencies=[KNOX, RANGER, DATA_ANALYTICS_STUDIO, HIVE])
    ]

  def check_dependencies(self, cluster, user):
    print '\nWhich DataPlane applications do you want to use with this cluster?'
    self.select_apps(user)
    print '\nChecking Ambari and your %s ...' % cluster
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

  def public_key(self):
    _, key = self.client.get('public-key', response_transformer=lambda url, code, data: (code, data))
    key = key.strip()
    if key.startswith('-----BEGIN CERTIFICATE-----'):
      key = key[len('-----BEGIN CERTIFICATE-----'):]
    if key.endswith('-----END CERTIFICATE-----'):
      key = key[:-len('-----END CERTIFICATE-----')]
    return key

  def register_ambari(self, ambari, knox, user):
    _, resp = self.client.post(
      'api/lakes',
      data=self.registration_request(ambari, knox, user),
      headers=[Header.content_type('application/json'), self.token_cookies()]
    )
    return resp

  def registration_request(self, ambari, knox, user):
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
      atlas_api = self.atlas_api(),
      dpprofiler = self.dpprofiler(),
      beacon = self.beacon(),
      streamsmsgmgr = self.streamsmsgmgr(),
      das = self.das()
    )
    return knox.add_topology(self.name, template)

  def ranger(self):
    return self.role('RANGER', self.ranger_url()) if 'RANGER' in self.role_names else ''

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
  def __init__(self, base_url, knox_user, knox_group, topology_directory='/etc/knox/conf/topologies'):
    self.base_url = base_url
    self.knox_user = knox_user
    self.knox_group = knox_group
    self.topology_directory = self._check_dir(topology_directory)

  def _check_dir(self, topology_directory):
    if not os.path.isdir(topology_directory):
      raise RuntimeError('Knox topology directory does not exist: %s' % topology_directory)
    return topology_directory

  def add_topology(self, topology_name, content):
    target = '%s/%s.xml' % (self.topology_directory, topology_name)
    print 'Saving topology %s' % target
    with open(target, 'w') as f: f.write(content)
    print '  Changing ownership of %s to %s:%s.' % (topology_name, self.knox_user, self.knox_group)
    os.chown(target, pwd.getpwnam(self.knox_user).pw_uid, grp.getgrnam(self.knox_group).gr_gid)
    print '  Changing permissions of %s to %o.' % (topology_name, 0644)
    os.chmod(target, 0644)

class AmbariPrerequisites:
  def __init__(self, ambari):
    self.ambari = ambari
    self.knox_host = ambari.cluster.knox_host()

  def satisfied(self):
    if not self.stack_supported():
      print 'The stack version (%s) is not supported. Supported stacks are: HDP-3.1 or newer.' % self.ambari.installed_stack()
      return False
    if not self.security_type_supported():
      print 'Your cluster is not kerberied. Please enable Kerberos using Ambari first.'
      return False
    if not ambari.kerberos_enabled():
      print 'Kerberos is not enabled for Ambari. Please enable it by running: ambari-server setup-kerberos from your Ambari Server host.'
      return False
    if not self.running_on_knox_host():
      print 'This script should be executed on the same host where Knox gateway is running (%s).' % self.knox_host
      return False
    return True

  def stack_supported(self):
    stack = self.ambari.installed_stack()
    return stack.name == 'HDP' and stack.version.startswith('3.1')

  def security_type_supported(self):
    return self.ambari.cluster.security_type == 'KERBEROS'

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

if __name__ == '__main__':
  user = Memorized(User())
  print '\nThis script will check to ensure that all necessary pre-requisites have been met and then register this cluster with DataPlane.\n'
  print 'Please ensure that your cluster has kerberos enabled, Ambari has been configured to use kerberos for authentication, and Knox is installed. Once those steps have been done, run this script from the Knox host and follow the steps and prompts to complete the cluster registration process.\n'

  if not ScriptPrerequisites().satisfied():
    sys.exit(1)

  print 'Tell me about your DataPlane Instance'
  dp = DataPlain(user.url_input('DataPlane URL', 'dp.url'), user.credential_input('DP Admin', 'dp.admin'))

  print "\nTell me about this cluster's Ambari Instance"
  ambari = Ambari(user.url_input('Ambari URL', 'ambari.url'), user.credential_input('Ambari admin', 'ambari.admin'))

  if not AmbariPrerequisites(ambari).satisfied():
    sys.exit(1)
  if dp.check_dependencies(ambari.cluster, user):
    sys.exit(1)

  knox = Knox(user.url_input('Knox URL that is network accessible from DataPlane', 'knox.url', default=str(ambari.cluster.knox_url())), knox_user=ambari.cluster.knox_user(), knox_group=ambari.cluster.knox_group())
  for topology in [TokenTopology(dp.public_key()), DpProxyTopology(ambari, dp.dependency_names())]:
    print 'Deploying Knox topology:', topology.name
    topology.deploy(knox)

  if 'RANGER' in dp.dependency_names():
    ambari.enable_trusted_proxy_for_ranger()
  if 'ATLAS' in dp.dependency_names():
    ambari.enable_trusted_proxy_for_atlas()
  ambari.enable_trusted_proxy_for_ambari()

  print 'Cluster changes are complete! Please log into Ambari, confirm the changes made to your cluster as part of this script and restart affected services.'
  user.any_input()

  print 'Registering cluster to DataPlane...'
  response = dp.register_ambari(ambari, knox, user)
  print 'Cluster is registered with id', response['id']

  print 'Success! You are all set, your cluster is registered and ready to use.'
