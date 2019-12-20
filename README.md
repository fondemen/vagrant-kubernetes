# vagrant-kubernetes
Starting up a Kubernetes cluster with Vagrant and VirtualBox.

```
vagrant up
# VMs need to be restarted after install...
vagrant halt
vagrant up
# Now you can login
vagrant ssh
# You are no able to play with kubectl, docker, helm
kubectl get pods
```

Created nodes are k8s01 (master), k8s02, k8s03 and so on (depends on [NODES](#nodes) variable).

[PersistentVolumeClaims](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#persistentvolumeclaims) are provisionned by [Heketi](https://github.com/heketi/heketi) / [GlusterFS](https://www.gluster.org/). A new disk is provisionned for each VM dedicated to storage at `~/VirtualBox\ VMs/k8s0X/gluster-k8s0X.vdi`. Key for Heketi to communicate with worker nodes is generated on the fly.

[Ingresses](https://kubernetes.io/docs/concepts/services-networking/ingress/) are served by [Traefik v1](https://docs.traefik.io/v1.7/user-guide/kubernetes/) on port 30080, proxied from port 80 by [nginx](https://nginx.org/). The traefik dashboard is available at http://192.168.2.100:30088.

Special thanks to [MM. Meyer and Schmuck](https://github.com/MeyerHerve/Projet3A-Kubernetes) for the installation procedure...

## configuration

Configuration is performed using environment variables:

### Cluster configuration

#### DOCKER_VERSION
The version of Docker to install. Check with `apt madison docker-ce`. Keep it in sync with [K8S_VERSION](#k8s_version) (see [changelog](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.17.md)). Setting this to `0` or `false` disables docker installation.
Default is 19.03.

#### K8S_VERSION
The version of Kubernetes to install. Keep it in sync with [DOCKER_VERSION](#docker_version) (see [changelog](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.17.md)). Setting this to `0` or `false` disables kubernetes installation.
Default is 1.17.0.

#### HELM_VERSION
The version of [Helm](https://helm.sh/) to install. Check https://github.com/helm/helm/releases. Note that you can [control](#tiller_ns) the kubernetes namespace used by tiller.
Default is 2.16.1.

#### TILLER_NS
The namespace in which tiller is to be installed by helm.
Default is tiller.

### Storage configuration

#### GLUSTER
Wether to install Gluster and Heketi.
Default is true.

#### GLUSTER_VERSION
The version of GlusterFS to install. Setting this of [GLUSTER](#gluster) to `0` or `false` disables kubernetes installation.
Default is 7.

#### GLUSTER_SIZE
Size in GiB of the GlusterFS-dedicated additional partition. A new disk of this size is to be created for each VM.
Default is 60.

#### HEKETI_VERSION
The version of Heketi to install (see https://github.com/heketi/heketi/releases).
Default is 9.0.0.

#### HEKETI_ADMIN
Admin password for Heketi.

#### HEKETI_PASSWORD
User passsword for Heketi.

### Ingress configuration

#### TRAEFIK
Whether to install traefik.
Default is true.

### Nodes configuration

#### NODES
The number of nodes in the cluster (including master).
Default is 3 (minimum required for Heketi, could be 2 if setting [GLUSTER](#gluster) to 0)

#### MEM
The memory used by each worker VM (in MB)
Default is 2048.

#### CPU
The number of CPUs for worker nodes
Default is 1.

#### MASTER_MEM
The memory used by the master VM (in MB)
Default is 4096.

#### MASTER_CPU
The number of CPUs for the master node
Default is 2.

#### PUBLIC_ROOT_KEY
The public key used for pasphraseless ssh between node. It's the same key for each node. Should be synchronized with [PRIVATE_ROOT_KEY](#private_root_key). You're encouraged to change the default value.

#### PRIVATE_ROOT_KEY
The private key used for pasphraseless ssh between node. Should be synchronized with [PUBLIC_ROOT_KEY](#public_root_key). It's the same key for each node. You're encouraged to change the default value.

#### BOX
The image to use. It must be Debian-based. So far, only tested with bento/debian-10.
Default is bento/debian-10.

#### PREFIX
The name prefix for VMs. The final VM name is the prefix followed by VM number using 2 digits.
Default value is k8s.

#### MASTER_IP
The IP of the first node (e.g. k8s01), that is the master node. Other nodes have the same IP + their node number -1, e.g. if node 0 is 192.168.2.100, then node 3 is 192.168.2.102.
Default value is 192.168.2.100.

#### GUEST_ADDITIONS
Whether to check for VirtualBox guest additions.
Default is false.

#### UPGRADE
Whether to upgrade OS.
Default is false.