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

import sys
import pprint
pp = pprint.PrettyPrinter(indent=4)

##-----------------
## Local imports
##-----------------
from dp_cluster_reg.exceptions import UnexpectedHttpCode
from dp_cluster_reg import FlowManager, BColors, ScriptPrerequisites
from dp_cluster_reg.config import user
 

"""
  Execution Starts here
"""  
if __name__ == '__main__':

  print BColors.HEADER
  print '\nThis script will check to ensure that all necessary pre-requisites have been met and then register this cluster with DataPlane.'
  print '\nThis script works with Cluster manager - Ambari or Cloudera Manager.'
  print BColors.BOLD + '\nIf you are Working with HDP/HDF Clusters managed by Ambari : ' + BColors.ENDC
  print BColors.HEADER
  print '\nPlease ensure that your cluster has kerberos enabled, Ambari has been configured to use kerberos for authentication, and Knox is installed. Once those steps have been done, run this script from the Knox host and follow the steps and prompts to complete the cluster registration process.\n'
  print BColors.BOLD + '\nIf you are Working with CDH clusters managed by Cloudera Manager :' + BColors.ENDC
  print BColors.HEADER
  print '\nPlease ensure you are running from one of the hosts of the cluster\n'
  print BColors.ENDC

  # Get the cluster type and execute the flow

  print BColors.BOLD + 'Tell me about your Cluster type' + BColors.ENDC
  flow_manager = FlowManager(user.cluster_type_input('Cluster Type ','cluster.type'))
  flow_manager.initialize()

  # root user is not required for CDH based clusters.
  # hence ScriptPrerequisites check is not required for CDH clusters

  if not flow_manager.cluster_type == 'CDH':
    if not ScriptPrerequisites().satisfied():
      sys.exit(1)
  exit_code = flow_manager.execute()
  sys.exit(exit_code)
