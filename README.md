# Hortonworks DataPlane Cluster Setup Utility
Registering clusters managed by Ambari/Cloudera Manager in dataplane.

**Installing**
- download latest release

```curl https://raw.githubusercontent.com/hortonworks/dp-cluster-reg/master/install.sh |sh```
- download a release

```export SCRIPT_RELEASE=1.0.0-alpha;curl https://raw.githubusercontent.com/hortonworks/dp-cluster-reg/master/install.sh |sh```

## Getting started with HDP/HDF clusters managed by Ambari
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

## Getting started with CDH clusters managed by Cloudera Manager
This utility helps in registering a Cloudera Manager managed CDH cluster in Dataplane

**Prerequisites**
- A DataPlane instance running 1.3 (or later)
- A Cloudera Manager managed cluster

**Installing**
- download the release on one of the cluster hosts.
- install dependencies
 ```bash
 pip install -r requirements.txt
 ``` 

 **Running the Script**
```
python dp-cluster-setup-utility.py
```

