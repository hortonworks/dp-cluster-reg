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
import urllib2
import warnings

from contextlib import closing
from dp_cluster_reg.rest import PermissiveSslContext, SslContext
from dp_cluster_reg.rest import JsonTransformer

try:
    import cm_client
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    warnings.warn('cm_client failed to import', ImportWarning)


class CMRestClient:
    def __init__(self, url, credentials):
        self.url = url
        self.credentials = credentials
        self.client = self._get_basic_client(url, credentials)

    def _get_basic_client(self, api_url, cred):
        cm_client.configuration.username = cred.user
        cm_client.configuration.password = cred.password
        cm_client.configuration.verify_ssl = False
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

    def host_resource_api(self):
        return cm_client.HostsResourceApi(self.client)


class RestClient:
    @classmethod
    def forJsonApi(
            cls,
            url,
            credentials,
            headers=[],
            ssl_context=PermissiveSslContext(),
            request_transformer=json.dumps):
        return cls(
            url,
            credentials,
            headers=headers,
            ssl_context=ssl_context,
            request_transformer=request_transformer,
            response_transformer=JsonTransformer())

    def __init__(self,
                 an_url,
                 credentials,
                 headers=[],
                 ssl_context=SslContext(),
                 request_transformer=lambda r: r,
                 response_transformer=lambda url, code, data: (code, data),
                 timeout=60):
        self.base_url = an_url
        self.credentials = credentials
        self.default_headers = headers
        self.ssl_context = ssl_context
        self.request_transformer = request_transformer
        self.response_transformer = response_transformer
        self.timeout = timeout

    def get(self, suffix_str, response_transformer=None, headers=[]):
        request, ssl_context = self._request(
            suffix_str, 'GET', self.request_transformer, headers=headers)
        return self._response(
            request,
            ssl_context,
            response_transformer or self.response_transformer)

    def delete(self, suffix_str, response_transformer=None, headers=[]):
        request, ssl_context = self._request(
            suffix_str, 'DELETE', self.request_transformer, headers=headers)
        return self._response(
            request,
            ssl_context,
            response_transformer or self.response_transformer)

    def post(
            self,
            suffix_str,
            data,
            request_transformer=None,
            response_transformer=None,
            headers=[]):
        request, ssl_context = self._request(
            suffix_str,
            'POST',
            request_transformer or self.request_transformer,
            data=data, headers=headers)
        return self._response(
            request,
            ssl_context,
            response_transformer or self.response_transformer)

    def put(
            self,
            suffix_str,
            data,
            request_transformer=None,
            response_transformer=None,
            headers=[]):
        request, ssl_context = self._request(
            suffix_str,
            'PUT',
            request_transformer or self.request_transformer,
            data=data, headers=headers)
        return self._response(
            request,
            ssl_context,
            response_transformer or self.response_transformer)

    def _request(
            self,
            suffix_str,
            http_method,
            request_transformer,
            data="",
            headers=[]):
        url = str(self.base_url / suffix_str)
        request = urllib2.Request(url, data=request_transformer(data))
        request.get_method = lambda: http_method
        for each in [self.credentials] + self.default_headers + headers:
            each.add_to(request)
        return request, self.ssl_context.build()

    def _response(self, request, ssl_context, response_transformer):
        try:
            with closing(urllib2.urlopen(
                                request,
                                context=ssl_context,
                                timeout=self.timeout
                                )
                         ) as response:
                return response_transformer(
                    request.get_full_url(),
                    response.getcode(),
                    response.read())
        except urllib2.HTTPError as e:
            print '* Error while requesting URL: %s' % request.get_full_url()
            print '* Error message: %s' % e.read()
            raise e
        except urllib2.URLError as e:
            print '* Error while requesting URL: %s' % request.get_full_url()
            raise e

    def rebased(
            self,
            new_base_url,
            request_transformer=None,
            response_transformer=None):
        return RestClient(
            new_base_url,
            self.credentials,
            self.default_headers,
            self.ssl_context,
            request_transformer if request_transformer else self.request_transformer,  # noqa
            response_transformer if response_transformer else self.response_transformer)  # noqa


class CookieThief:
    def __init__(self):
        self.cookie_proc = urllib2.HTTPCookieProcessor()
        self.opener = urllib2.build_opener(
            urllib2.HTTPSHandler(
                context=self._ssl_context()),
            self.cookie_proc)

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
