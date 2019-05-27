
class BaseCluster(object):
    def has_service(self, service_name):
        return service_name in self.service_names()
