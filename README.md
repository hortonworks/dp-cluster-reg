# Hortonworks DataPlane Cluster Setup Utility
Registering clusters managed by Ambari/Cloudera Manager in dataplane.

## Getting started with HDP/HDF clusters managed by Ambari
This utility helps configure your cluster with Knox Trusted Proxy support, establishes the trust
relationship between DataPlane and the cluster, and registers the cluster with DataPlane.

**Prerequisites**
- A DataPlane instance running 1.2.1 (or later)
- An Ambari-managed cluster that includes Knox
- Kerberos-enabled cluster
- Ambari configured for Kerberos Authentication
- DataPlane Cluster Agents (for the DataPlane Apps you plan to use) should be installed & configured in the cluster

**Installing**
- download latest release

```bash 
curl https://raw.githubusercontent.com/hortonworks/dp-cluster-reg/master/install.sh |sh
```

- download a release

```
export RELEASE=<release-name>;curl https://raw.githubusercontent.com/hortonworks/dp-cluster-reg/master/install.sh |sh
```
   
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

### download release and install dependencies manually

- latest release 
```
curl https://raw.githubusercontent.com/hortonworks/dp-cluster-reg/master/install.sh |sh
```

- given release
```
export RELEASE=<release>;curl https://raw.githubusercontent.com/hortonworks/dp-cluster-reg/master/install.sh |sh
```
  
- install dependencies
```
pip install -r requirements.txt
``` 
### download release and install dependencies automatically
- latest release
```
export CM=true;curl https://raw.githubusercontent.com/hortonworks/dp-cluster-reg/master/install.sh |sh
```

- given release
```
export CM=true;export RELEASE=<release>;curl https://raw.githubusercontent.com/hortonworks/dp-cluster-reg/master/install.sh |sh
```

 **Running the Script**
```
python dp-cluster-setup-utility.py
```

**unset export parameters**
```
unset CM;unset RELEASE
```
