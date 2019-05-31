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

import os
import pwd
import grp
from shutil import copyfile
from dp_cluster_reg.rest import RestClient, Header
from dp_cluster_reg import config
from dp_cluster_reg.exceptions import UnexpectedHttpCode

class Knox:
    def __init__(self, base_url, knox_user, knox_group,
                 topology_directory='/etc/knox/conf/topologies'):
        self.base_url = base_url
        self.knox_user = knox_user
        self.knox_group = knox_group
        self.topology_directory = self._check_dir(topology_directory)

    def _check_dir(self, knox_artifact_directory, artifact_type='topology'):
        if not os.path.isdir(knox_artifact_directory):
            raise RuntimeError(
                'Knox %s directory does not exist: %s' %
                (artifact_type, knox_artifact_directory))
        return knox_artifact_directory

    def _check_file(self, service_file):
        if not os.path.isfile(service_file):
            raise RuntimeError(
                'Knox service file does not exist: %s' %
                service_file)
        return service_file

    def _chown_to_knox(self, path_name):
        os.chown(
            path_name, pwd.getpwnam(
                self.knox_user).pw_uid, grp.getgrnam(
                self.knox_group).gr_gid)

    def add_topology(self, topology_name, content):
        target = '%s/%s.xml' % (self.topology_directory, topology_name)
        print 'Saving topology %s' % target
        with open(target, 'w') as f:
            f.write(content)
        print '  Changing ownership of %s to %s:%s.' % (
            topology_name, self.knox_user, self.knox_group)
        self._chown_to_knox(target)
        print '  Changing permissions of %s to %o.' % (topology_name, 0o644)
        os.chmod(target, 0o644)

    def _create_service_file(self, service, version, file_name, service_dir):
        dest_file = '%s/%s' % (service_dir, file_name)
        # src_file = self._check_file('%s/services/%s/%s/%s' % (os.path.dirname(os.path.realpath(__file__)), service, version, file_name))
        src_file = self._check_file(
            '%s/services/%s/%s/%s' %
            (config.SERVICE_CONF_DIR, service, version, file_name))
        copyfile(src_file, dest_file)
        self._chown_to_knox(dest_file)

    def update_profiler_agent_service_def(self, current_stack_version):
        dest_services_base_dir = self._check_dir(
            '/var/lib/knox/data-%s/services' %
            current_stack_version, 'service')
        service_dir = '%s/profiler-agent/1.0.0' % dest_services_base_dir
        self._execute_service_conf_file_copy_task(
            "profiler-agent", "1.0.0", service_dir)

    def update_ambari_service_def(self, current_stack_version):
        dest_services_base_dir = self._check_dir(
            '/var/lib/knox/data-%s/services' %
            current_stack_version, 'service')
        service_dir = '%s/ambari/0.2.2.0' % dest_services_base_dir
        self._execute_service_conf_file_copy_task(
            "ambari", "0.2.2.0", service_dir)

    def _execute_service_conf_file_copy_task(
            self, service, version, service_dir):
        if os.path.isdir(service_dir):
            print 'Service files already exist in %s' % service_dir
        else:
            os.makedirs(service_dir)

        self._create_service_file(service, version, 'rewrite.xml', service_dir)
        self._create_service_file(service, version, 'service.xml', service_dir)

        self._chown_to_knox(service_dir)
        self._chown_to_knox(os.path.dirname(service_dir))


class KnoxAdminApi:
    def __init__(self, url, credentials):
        self.base_url = url
        self.credentials = credentials
        self.client = RestClient.forJsonApi(
            self.base_url, credentials, request_transformer=str)

    def add_topology(self, topology, xml_data):
        topology_api = self.base_url / 'gateway/admin/api/v1/topologies' / topology
        code, resp = self.client.put(
            topology_api, xml_data, headers=[
                Header.content_type('application/xml'), Header.accept_json()])
        if code != 200:
            raise UnexpectedHttpCode(
                'Unexpected HTTP code: %d url: %s response: %s' %
                (code, topology_api, resp))
        elif code == 200:
            print 'Successfully deployed topology: %s' % (topology)
