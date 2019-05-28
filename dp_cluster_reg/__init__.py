"""
dp-cluster-reg - a tool to onboard clusters managed by Ambari and Cloudera Manager on Dataplane
"""
__version__ = '1.0.0'

# Check minimum required Python version
import sys
if sys.version_info < (2, 7):
    print("dp-cluster-reg %s requires Python 2.7" % __version__)
    sys.exit(1)


# imports

from .helpers import BColors, ScriptPrerequisites
from .registrationflow import FlowManager
from .userinput import User
