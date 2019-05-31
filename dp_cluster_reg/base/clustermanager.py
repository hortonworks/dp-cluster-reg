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
