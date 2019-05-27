import os
from .dataplane import Dependency
from .userinput import Memorized, User

# Service Dependency matrix for Ambari managed cluster

# Service Dependency matrix for Cloudera Manager managed cluster

# Directory in which service configuration files are present
SERVICE_CONF_DIR = '%s/data' % os.path.dirname(
    (os.path.dirname(os.path.realpath(__file__))))

# Global user variable
user = Memorized(User())
