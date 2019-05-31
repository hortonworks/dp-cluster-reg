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

import time
class Dependency:
    def __init__(self, service_name, display_name):
        self.service_name = service_name
        self.display_name = display_name

    def __eq__(self, that): return isinstance(that, type(
        self)) and self.service_name == that.service_name

    def __hash__(self): return hash(self.service_name)


class Tag:
    @classmethod
    def random(self, name): return self("%s-%s" % (name, time.time()))
    def __init__(self, name): self.name = name
    def __str__(self): return self.name
