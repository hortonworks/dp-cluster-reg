import time


class TokenTopology:
    TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
  <topology>
     <uri>{knox_url}/gateway/token</uri>
     <name>token</name>
     <timestamp>{timestamp}</timestamp>
     <generated>false</generated>
     <gateway>
        <provider>
           <role>federation</role>
           <name>SSOCookieProvider</name>
           <enabled>true</enabled>
           <param>
              <name>sso.authentication.provider.url</name>
              <value>{knox_url}/gateway/knoxsso/api/v1/websso</value>
           </param>
           <param>
              <name>sso.token.verification.pem</name>
              <value>{pem}</value>
           </param>
        </provider>
        <provider>
           <role>identity-assertion</role>
           <name>HadoopGroupProvider</name>
           <enabled>true</enabled>
        </provider>
     </gateway>
     <service>
        <role>KNOXTOKEN</role>
        <param>
           <name>knox.token.ttl</name>
           <value>{token_ttl}</value>
        </param>
        <param>
           <name>knox.token.client.data</name>
           <value>cookie.name=hadoop-jwt</value>
        </param>
     </service>
  </topology>"""

    def __init__(self, pem, name='token', token_ttl=100000):
        self.pem = pem
        self.name = name
        self.token_ttl = token_ttl

    def deploy(self, knox):
        template = TokenTopology.TEMPLATE.format(
            knox_url=str(knox.base_url),
            timestamp=int(time.time()),
            pem=self.pem,
            token_ttl=self.token_ttl
        )
        return knox.add_topology(self.name, template)


class DpProxyTopology:
    TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
  <topology>
     <uri>{knox_url}/gateway/dp-proxy</uri>
     <name>dp-proxy</name>
     <timestamp>{timestamp}</timestamp>
     <generated>false</generated>
     <gateway>
        <provider>
           <role>federation</role>
           <name>SSOCookieProvider</name>
           <enabled>true</enabled>
           <param>
              <name>sso.authentication.provider.url</name>
              <value>{knox_url}/gateway/knoxsso/api/v1/websso</value>
           </param>
        </provider>
        <provider>
           <role>identity-assertion</role>
           <name>Default</name>
           <enabled>true</enabled>
        </provider>
     </gateway>
     {cluster_manager}
     {ranger}
     {atlas_api}
     {dpprofiler}
     {beacon}
     {streamsmsgmgr}
  </topology>"""

    def get_template(self, knox, topology_util):
        return DpProxyTopology.TEMPLATE.format(
            knox_url=str(knox.base_url),
            timestamp=int(time.time()),
            cluster_manager=topology_util.cluster_manager(),
            ranger=topology_util.ranger(),
            atlas_api=topology_util.atlas_api(),
            dpprofiler=topology_util.dpprofiler(),
            beacon=topology_util.beacon(),
            streamsmsgmgr=topology_util.streamsmsgmgr(),
        )


class DpProxyTopologyForAmbari(DpProxyTopology):
    def __init__(self, ambari, role_names, topology_util, name='dp-proxy'):
        self.ambari = ambari
        self.role_names = role_names
        self.name = name
        self.topology_util = topology_util

    def deploy(self, knox):
        self.update_knox_service_defs(knox)
        template = self.get_template(knox, self.topology_util)
        return knox.add_topology(self.name, template)

    def update_knox_service_defs(self, knox):
        stack = self.ambari.installed_stack()
        if 'DPPROFILER' in self.role_names:
            if stack.name == 'HDP':
                stack_version = self.ambari.current_stack_version()
                knox.update_profiler_agent_service_def(stack_version)
        if stack.name == 'HDF':
            stack_version = self.ambari.current_stack_version()
            knox.update_ambari_service_def(stack_version)


class DpProxyTopologyForCM(DpProxyTopology):
    def __init__(self, cm, role_names, topology_util, name='dp-proxy'):
        self.cm = cm
        self.role_names = role_names
        self.name = name
        self.topology_util = topology_util

    def deploy(self, knox):
        template = self.get_template(knox, self.topology_util)
        return knox.add_topology(self.name, template)


class BeaconProxyTopology:
    TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
  <topology>
     <uri>{knox_url}/gateway/beacon-proxy</uri>
     <name>beacon-proxy</name>
     <timestamp>{timestamp}</timestamp>
     <generated>false</generated>
     <gateway>
        <provider>
          <role>authentication</role>
          <name>HadoopAuth</name>
          <enabled>true</enabled>
          <param>
            <name>config.prefix</name>
            <value>hadoop.auth.config</value>
          </param>
          <param>
            <name>hadoop.auth.config.signature.secret</name>
            <value>knox-signature-secret</value>
          </param>
          <param>
            <name>hadoop.auth.config.type</name>
            <value>kerberos</value>
          </param>
          <param>
            <name>hadoop.auth.config.simple.anonymous.allowed</name>
            <value>false</value>
          </param>
          <param>
            <name>hadoop.auth.config.token.validity</name>
            <value>1800</value>
          </param>
          <param>
            <name>hadoop.auth.config.cookie.domain</name>
            <value>{realm}</value>
          </param>
          <param>
            <name>hadoop.auth.config.cookie.path</name>
            <value>gateway/beacon-proxy</value>
          </param>
          <param>
            <name>hadoop.auth.config.kerberos.principal</name>
            <value>HTTP/{knox_host}@{realm}</value>
          </param>
          <param>
            <name>hadoop.auth.config.kerberos.keytab</name>
            <value>/etc/security/keytabs/spnego.service.keytab</value>
          </param>
          <param>
            <name>hadoop.auth.config.kerberos.name.rules</name>
            <value>DEFAULT</value>
          </param>
        </provider>
        <provider>
            <role>identity-assertion</role>
            <name>Default</name>
            <enabled>true</enabled>
        </provider>
     </gateway>
     {ranger}
     {atlas_api}
     {beacon}
  </topology>"""

    def __init__(self, ambari, role_names, topology_util, name='beacon-proxy'):
        self.ambari = ambari
        self.role_names = role_names
        self.name = name
        self.topology_util = topology_util

    def deploy(self, knox):
        template = BeaconProxyTopology.TEMPLATE.format(
            knox_url=str(knox.base_url),
            knox_host=self.ambari.cluster.knox_host(),
            realm=self.ambari.cluster.cluster_realm(),
            timestamp=int(time.time()),
            ranger=self.topology_util.ranger(),
            atlas_api=self.topology_util.atlas_api(),
            beacon=self.topology_util.beacon(),
        )
        return knox.add_topology(self.name, template)


class RedirectTopology:
    TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
  <topology>
    <name>tokensso</name>
    <gateway>
        <provider>
            <role>federation</role>
            <name>JWTProvider</name>
            <enabled>true</enabled>
        </provider>
        <provider>
            <role>identity-assertion</role>
            <name>Default</name>
            <enabled>true</enabled>
        </provider>
    </gateway>
    <service>
        <role>KNOXSSO</role>
        <param>
            <name>knoxsso.cookie.secure.only</name>
            <value>true</value>
        </param>
        <param>
            <name>knoxsso.token.ttl</name>
            <value>600000</value>
        </param>
        <param>
            <name>knoxsso.redirect.whitelist.regex</name>
            <value>^https?:\/\/.*$</value>
        </param>
    </service>
  </topology>"""

    def __init__(self, name='redirect'):
        self.name = name

    def deploy(self, knox):
        print ' Please be aware: Adding a wildcard as the value for knoxsso.redirect.whitelist.regex in %s topology. You can edit this topology file to set a more restrictive value.' % self.name
        return knox.add_topology(self.name, RedirectTopology.TEMPLATE)
