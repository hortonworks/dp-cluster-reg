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

from dp_cluster_reg.base import BasePrerequisites


class AmbariPrerequisites(BasePrerequisites):
    def __init__(self, ambari):
        self.ambari = ambari
        self.knox_host = ambari.cluster.knox_host()

    def satisfied(self):
        if not self.stack_supported():
            print 'The stack version (%s) is not supported. Supported stacks are: HDP-2.6/HDP-3.1/HDF-3.3 or newer.' % self.ambari.installed_stack()  # noqa
            return False
        if not self.security_type_supported():
            print 'Your cluster is not kerberied. Please enable Kerberos using Ambari first.'  # noqa
            return False
        if not self.ambari.kerberos_enabled():
            print 'Kerberos is not enabled for Ambari. Please enable it by running: ambari-server setup-kerberos from your Ambari Server host.'  # noqa
            return False
        if self.ambari.installed_stack().version.startswith(
                '2.6') and not self.ambari.trusted_proxy_enabled():
            print 'Trusted Proxy is not enabled for Ambari. Please enable it by running: ambari-server setup-trusted-proxy from your Ambari Server host.'  # noqa
            return False
        if not self.running_on_knox_host():
            print 'This script should be executed on the same host where Knox gateway is running (%s).' % self.knox_host  # noqa
            return False
        return True

    def stack_supported(self):
        return self.hdp_supported_version() or self.hdf_supported_version()

    def hdp_supported_version(self):
        stack = self.ambari.installed_stack()
        return stack.name == 'HDP' and (
            stack.version.startswith('3.1') or stack.version.startswith('2.6'))

    def hdf_supported_version(self):
        stack = self.ambari.installed_stack()
        return stack.name == 'HDF' and stack.version.startswith('3.3')

    def security_type_supported(self):
        return self.ambari.cluster.security_type == 'KERBEROS'
