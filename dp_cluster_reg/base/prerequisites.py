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

"""Base implementation of a prerequisites interface."""
import socket


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
