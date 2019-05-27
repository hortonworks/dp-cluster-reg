"""
dp-cluster-reg - a tool to onboard clusters managed by Ambari and Cloudera Manager on Dataplane
"""

# Check minimum required Python version
import sys
if sys.version_info < (2, 7):
    print("dp-cluster-reg %s requires Python 2.7" % __version__)
    sys.exit(1)


# imports

from .helpers import BColors, ScriptPrerequisites
from .registrationflow import FlowManager
from .userinput import User

""""
# db.py
import sys

# this is a pointer to the module object instance itself.
this = sys.modules[__name__]

# we can explicitly make assignments on it 
this.db_name = None

def initialize_db(name):
    if (this.db_name is None):
        # also in local function scope. no scope specifier like global is needed
        this.db_name = name
        # also the name remains free for local use
        db_name = "Locally scoped db_name variable. Doesn't do anything here."
    else:
        msg = "Database is already initialized to {0}."
        raise RuntimeError(msg.format(this.db_name))
"""