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
import getpass

from urlparse import urlparse
from dp_cluster_reg.rest import Url, Credentials


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
        def describe_failure(self): print 'Invalid option, please choose from: %s' % (
            ', '.join(self.options))

    class YesNo(Options):
        def __init__(self): InputValidator.Options.__init__(self, ('y', 'n'))

    class ClusterType(Options):
        def __init__(self): InputValidator.Options.__init__(
            self, ('HDP', 'HDF', 'CDH'))

    class Url:
        def valid(self, input):
            if not (input.startswith('http://')
                    or input.startswith('https://')):
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
        return self.input(
            prompt,
            name,
            default='y' if default else 'n',
            validator=InputValidator.YesNo()) == 'y'

    def input(
            self,
            prompt,
            id,
            default="",
            sensitive=False,
            validator=InputValidator.NonBlank()):
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
        return Url(
            self.input(
                '%s (http(s)://host:[port])' %
                name,
                id,
                validator=InputValidator.Url(),
                default=default))

    def credential_input(
            self,
            name,
            id,
            default_user=None,
            default_password=None):
        return Credentials(
            self.input(
                '%s username' %
                name,
                id,
                default=default_user),
            self.input(
                '%s password' %
                name,
                id,
                sensitive=True,
                default=default_password))

    def cluster_type_input(self, name, id, default_cluster_type=None):
        return ClusterType(
            self.input(
                '%s [HDP/HDF/CDH]' %
                name,
                id,
                validator=InputValidator.ClusterType(),
                default=default_cluster_type))

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

    def input(
            self,
            prompt,
            id,
            default="",
            sensitive=False,
            validator=InputValidator.NonBlank()):
        answer = self.user.input(prompt, id, default=self._get(
            id, default), sensitive=sensitive, validator=validator)
        if not sensitive:
            self._update({id: answer})
        return answer

    def url_input(self, name, id, default=None):
        answer = self.user.url_input(name, id, default=self._get(id, default))
        self._update({id: str(answer)})
        return answer

    def credential_input(
            self,
            name,
            id,
            default_user=None,
            default_password=None):
        key = "%s.user" % id
        answer = self.user.credential_input(
            name, id, default_user=self._get(
                key, default_user), default_password=default_password)
        self._update({key: answer.user})
        return answer

    def cluster_type_input(self, name, id, default_cluster_type=None):
        answer = self.user.cluster_type_input(
            name, id, default_cluster_type=self._get(
                id, default_cluster_type))
        self._update({id: answer.name})
        return answer

    def any_input(self, prompt='Press enter to continue'):
        return self.user.any_input(prompt)

    def _load(self):
        try:
            with open(self.file_name, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def _update(self, update):
        self.history.update(update)
        with open(self.file_name, 'w') as f:
            json.dump(self.history, f, indent=2)

    def _get(self, name, default):
        return self.history.get(name, "") or default
