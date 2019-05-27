from dp_cluster_reg.base import BasePrerequisites
from dp_cluster_reg import BColors


class CMPrerequisites(BasePrerequisites):
    def __init__(self, cm):
        self.cm = cm

    def satisfied(self):
        for cluster in self.cm.clusters:
            if not self.stack_supported(cluster):
                print BColors.BOLD
                print(
                    'The stack version (%s) is not supported for %s. Supported stacks are: CDH-5.17/CDH-6.1  or newer.' %
                    (cluster.installed_stack(), cluster.cluster_name))
                print BColors.ENDC
                return False
        if self.cm.total_clusters == 1:
            # knox related checks are only applicable when number of cluster
            # managed by CM = 1
            if not self.cm.kerberos_enabled():
                print BColors.BOLD
                print 'Kerberos is not enabled for Cloudera Manager. Please enable it first and then re-run the script.'  # noqa
                print BColors.ENDC
                return False
            if not self.cm.knox_rules_defined():
                print BColors.BOLD
                print 'Some of knox properties required for working with knox are not found in Cloudera Manager Configuration.'  # noqa
                print 'Set all of [PROXYUSER_KNOX_GROUPS, PROXYUSER_KNOX_HOSTS,PROXYUSER_KNOX_PRINCIPAL, PROXYUSER_KNOX_USERS] through ClouderaManager UI and restart cloudera manager server.'  # noqa
                print 'Re-run the script after the start is successful.'
                print BColors.ENDC
                return False
        return True

    def stack_supported(self, cluster):
        stack = cluster.installed_stack()
        check_version = False
        (major, minor) = stack.version.split('.')[:2]
        if (major == '5' and int(minor) >= 17) or (
                major == '6' and int(minor) >= 0):
            check_version = True
        return stack.name == 'CDH' and check_version
