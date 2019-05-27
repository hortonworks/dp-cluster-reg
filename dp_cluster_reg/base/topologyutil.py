class TopologyUtil:
    def __init__(self, role_names):
        self.role_names = role_names

    def ranger(self):
        return self.role(
            'RANGER',
            self.ranger_url(),
            '0.1.0.0') if 'RANGER' in self.role_names else ''

    def atlas_api(self):
        return self.role(
            'ATLAS-API',
            self.atlas_url(),
            '0.1.2.0') if 'ATLAS' in self.role_names else ''

    def dpprofiler(self):
        return self.role('PROFILER-AGENT', self.dpprofiler_url()
                         ) if 'DPPROFILER' in self.role_names else ''

    def beacon(self):
        return self.role('BEACON', self.beacon_url()
                         ) if 'BEACON' in self.role_names else ''

    def streamsmsgmgr(self):
        return self.role('SMM', self.streamsmsgmgr_url()
                         ) if 'STREAMSMSGMGR' in self.role_names else ''

    def role(self, name, url, version=''):
        version_str = ''
        if version:
            version_str = '<version>{version}</version>'.format(
                version=version)
        return """
    <service>
      <role>{role}</role>
      {version_str}
      <url>{url}</url>
    </service>""".format(role=name, url=url, version_str=version_str)
