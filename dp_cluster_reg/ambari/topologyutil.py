from dp_cluster_reg.base import TopologyUtil


class AmbariTopologyUtil(TopologyUtil):
    def __init__(self, ambari, role_names):
        self.ambari = ambari
        self.role_names = role_names

    def ranger_url(self):
        host = self.host_name('RANGER', 'RANGER_ADMIN')
        if self.ambari.cluster.config_property(
            'ranger-admin-site',
                'ranger.service.https.attrib.ssl.enabled') == 'true':
            port = self.ambari.cluster.config_property(
                'ranger-admin-site', 'ranger.service.https.port')
            return 'https://%s:%s' % (host, port)
        else:
            port = self.ambari.cluster.config_property(
                'ranger-admin-site', 'ranger.service.http.port')
            return 'http://%s:%s' % (host, port)

    def atlas_url(self):
        host = self.host_name('ATLAS', 'ATLAS_SERVER')
        if self.ambari.cluster.config_property(
            'application-properties',
                'atlas.enableTLS') == 'true':
            port = self.ambari.cluster.config_property(
                'application-properties', 'atlas.server.https.port')
            return 'https://%s:%s' % (host, port)
        else:
            port = self.ambari.cluster.config_property(
                'application-properties', 'atlas.server.http.port')
            return 'http://%s:%s' % (host, port)

    def dpprofiler_url(self):
        host = self.host_name('DPPROFILER', 'DP_PROFILER_AGENT')
        port = self.ambari.cluster.config_property(
            'dpprofiler-env', 'dpprofiler.http.port')
        return 'http://%s:%s' % (host, port)

    def beacon_url(self):
        host = self.host_name('BEACON', 'BEACON_SERVER')
        if self.ambari.cluster.config_property(
                'beacon-env', 'beacon_tls_enabled') == 'true':
            port = self.ambari.cluster.config_property(
                'beacon-env', 'beacon_tls_port')
            return 'https://%s:%s' % (host, port)
        else:
            port = self.ambari.cluster.config_property(
                'beacon-env', 'beacon_port')
            return 'http://%s:%s' % (host, port)

    def streamsmsgmgr_url(self):
        host = self.host_name('STREAMSMSGMGR', 'STREAMSMSGMGR')
        if self.ambari.cluster.config_property(
            'streams-messaging-manager-ssl-config',
                'streams_messaging_manager.ssl.isenabled') == 'true':
            port = self.ambari.cluster.config_property(
                'streams-messaging-manager-common',
                'streams_messaging_manager.ssl.port')
            return 'https://%s:%s' % (host, port)
        else:
            port = self.ambari.cluster.config_property(
                'streams-messaging-manager-common', 'port')
            return 'http://%s:%s' % (host, port)

    def cluster_manager(self):
        version = "0.2.2.0"
        ambari_protocol = self.ambari.base_url.protocol()
        ambari_host = self.ambari.internal_host
        ambari_port = self.ambari.base_url.port()
        url = "%s://%s:%s" % (ambari_protocol, ambari_host, ambari_port)
        return self.role('AMBARI', url, version)

    def host_name(self, service_name, component_name):
        return self.ambari.cluster.service(
            service_name).component(component_name).host_names()[0]
