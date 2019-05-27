from dp_cluster_reg.base import TopologyUtil


class CMTopologyUtil(TopologyUtil):
    def __init__(self, cm, role_names):
        self.cm = cm
        self.role_names = role_names

    def ranger_url(self):
        pass

    def atlas_url(self):
        pass

    def dpprofiler_url(self):
        pass

    def beacon_url(self):
        pass

    def streamsmsgmgr_url(self):
        pass

    def host_name(self, service_name, component_name):
        pass

    def cluster_manager(self):
        protocol = self.cm.base_url.protocol()
        netloc = self.cm.base_url.netloc()
        url = "%s://%s" % (protocol, netloc)
        return self.role('CM-API', url)
