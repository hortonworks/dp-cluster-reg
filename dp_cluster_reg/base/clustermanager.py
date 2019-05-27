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
