# Hortonworks DataPlane Cluster Setup Utility

This utility helps configure your cluster with Knox Trusted Proxy support, establishes the trust
relationship between DataPlane and the cluster, and registers the cluster with DataPlane.

**Prerequisites**
- A DataPlane instance running 1.2.1 (or later)
- An Ambari-managed cluster that includes Knox
- Kerberos-enabled cluster
- Ambari configured for Kerberos Authentication
- DataPlane Cluster Agents (for the DataPlane Apps you plan to use) should be installed & configured in the cluster

**Running the Script**
Run this script as ```root``` on the cluster host with your Knox server.

```
python dp-cluster-setup-utility.py
```

