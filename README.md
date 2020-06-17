# vagrant-kubernetes
Starting up a Kubernetes cluster with Vagrant and VirtualBox.

```
export PORTWORX_USER=[Portworx User ID]
vagrant box update # can fail safely
vagrant up
# Now you can login
vagrant ssh
# You are no able to play with kubectl, docker, helm
kubectl get pods
```

Created nodes are k8s01 (master), k8s02, k8s03 and so on (depends on [NODES](#nodes) and [PREFIX](#prefix) variables). Kubernetes Dashboard with admin rigths is available at http://192.168.2.100:8001/

Cluster can merly be stopped by issuing `vagrant halt` and later restarted with `vagrant up` (with same env vars!).

[PersistentVolumeClaims](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#persistentvolumeclaims) are provisionned by [Portworx](https://portworx.com/) Essentials as long as you supply you user ID using the PORTWORX_USER env var. To get your UserID, register a new spec on https://central.portworx.com/ (parameters are not used), and get the user parameter given by its "View Spec" action url. Main storage classes are "portworx-db-sc" (for ReadWriteOnce) and "portworx-shared-sc" for "ReadWriteMany". A [dasboard](http://192.168.2.100:8008) (with credentials admin:Password1) is available as long as the `pxcli` command. For your containers using Portworx volumes to be colocated with master copy of the volume, define the [`schedulerName: stork`](https://docs.portworx.com/portworx-install-with-kubernetes/storage-operations/hyperconvergence/) parameter.

If setting the GLUSTER=On env var, PersistentVolumeClaims can also be managed by [Heketi](https://github.com/heketi/heketi) / [GlusterFS](https://www.gluster.org/) using storage class "glusterfs". A new disk is provisionned for each VM dedicated to storage at `~/VirtualBox\ VMs/k8s0X/gluster-k8s0X.vdi`. Key for Heketi to communicate with worker nodes is generated on the fly.

[Ingresses](https://kubernetes.io/docs/concepts/services-networking/ingress/) are served by [Traefik](https://docs.traefik.io/providers/kubernetes-ingress/) on port 80. The traefik dashboard is available at http://192.168.2.100:9000/.

Special thanks to [MM. Meyer and Schmuck](https://github.com/MeyerHerve/Projet3A-Kubernetes) for the installation procedure...

## Testing

### Testing Portworx

Invoke `kubectl apply -f https://raw.githubusercontent.com/fondemen/vagrant-kubernetes/portworx/nginx-portworks.yml`. Within the next minute, you should find a [`nginx.local/` router](http://192.168.2.100/dashboard/#/http/routers/nginx-ingress-default-nginx-local@kubernetes) associated to a [servce with two backends](http://192.168.2.100/dashboard/#/http/services/default-nginx-service-80@kubernetes). `curl -H 'Host: nginx.local' 192.168.2.100` should return a 403 (as no file exists to be served).

To load a file, list portworx volumes with `pxctl volume list` : one volume should show up (the one created by the persistent volume claim - you can find the exact volume name with `kubectl get pv $(kubectl get pvc test-pvc -o jsonpath='{.spec.volumeName}') -o jsonpath='{.spec.portworxVolume.volumeID}'`). To load a file, run the following command: `k exec $(kubectl get pods -l run=nginx -o jsonpath='{.items[0].metadata.name}') -- /bin/sh -c 'echo "Hello World!" > /usr/share/nginx/html/index.html'`. Now `curl -H 'Host: nginx.local' 192.168.2.100` should return "Hello World!".

### Testing GlusterFS

Env var GLUSTER should be set to "On" *before* vagrant up is issued.

Invoke `kubectl apply -f https://raw.githubusercontent.com/fondemen/vagrant-kubernetes/master/nginx-test-file.yml`. Within the next minute, you should find a [`nginx.local/` router](http://192.168.2.100/dashboard/#/http/routers/nginx-ingress-default-nginx-local@kubernetes) associated to a [servce with two backends](http://192.168.2.100/dashboard/#/http/services/default-nginx-service-80@kubernetes). `curl -H 'Host: nginx.local' 192.168.2.100` should return a 403 (as no file exists to be served).

To load a file, `sudo su -` to get root access, list gluster volumes with `gluster volume list` : one volume should show up (the one created by the persistent volume claim). You can find the exact volume name with `kubectl get pv $(kubectl get pvc test-gluster-pvc -o jsonpath='{.spec.volumeName}') -o jsonpath='{.spec.glusterfs.path}'`. Create a directory (e.g. `mkdir nginx-data`), and mount that volume with `mount -t glusterfs k8s01:/[volume name] nginx-data`. Add an `index.html` file to `nginx-data` and then `curl -H 'Host: nginx.local' 192.168.2.100` should serve you that file.

## Remote access

To use [kubectl](https://kubernetes.io/fr/docs/reference/kubectl/overview/) directly from the host machine, do `vagrant ssh -c 'cat ~/.kube/config' > kubeconfig; export KUBECONFIG="$PWD/kubeconfig"`. Note that the exported config supplies full admin rights to the cluster.

Dashboards ([Kubernetes](#k8s_db_port) and [Traefik](#traefik_db_port)) can be exposed *unsecured* on the host machine by settig the EXPOSE_DB_PORTS env var to true *before* firing up the `vagrant up` or another `vagrant provision` in case the cluster already exists.

## Configuration

Configuration is performed using environment variables:

### Cluster configuration

#### DOCKER_VERSION
The version of Docker to install. Check with `apt madison docker-ce`. Keep it in sync with [K8S_VERSION](#k8s_version) (see [containner runtime installation](https://kubernetes.io/docs/setup/production-environment/container-runtimes/#docker)). Setting this to `0` or `false` disables Docker installation.
Default is 19.03.8.

#### K8S_VERSION
The version of Kubernetes to install. Keep it in sync with [DOCKER_VERSION](#docker_version) (see [containner runtime installation](https://kubernetes.io/docs/setup/production-environment/container-runtimes/#docker)). Setting this to `0` or `false` disables kubernetes installation.
Default is 1.18.2.

#### K8S_DB_PORT
The port at which exposing the Kubernetes Dashboard. Traefik must be [enabled](#traefik) for the dashboard to be visible. Set to 0 to disable.
Default is 8001.

#### K8S_DB_VERSION
The version of the dashboard to run. To be found at https://github.com/kubernetes/dashboard/tags (avoiding the initial v). Set to latest to get the latest version, or 0 to disable.
Default is latest.

#### CNI
The CNI provider to use. Currently supported options are flannel and calico.
Default is calico.

#### CALICO_VERSION
The version of calico to use.
Default is 3.13.

#### HELM_VERSION
The version of [Helm](https://helm.sh/) to install. Check https://github.com/helm/helm/releases. Note that you can [control](#tiller_ns) the kubernetes namespace used by tiller.
Default is 3.2.0.

#### TILLER_NS
The namespace in which tiller is to be installed by helm. This parameter is ignored in case [HELM_VERSION](#helm_version) is &ge; 3.
Default is tiller.

### Storage configuration

#### PORTWORX
Wether to install Portworx Essentials.
Default is true.

#### PORTWORX_USER
The Portworx User ID. This parameter is mandatory at cluster creation if you [enable Portworx](#portworx). It can be found by:
- going https://central.portworx.com/specGen and login/register
- clicking install and run
- creating a new spec if none exist (parameters are not used in this script)
- IF NOT USED ELSEWHERE unlinking cluster - see https://docs.portworx.com/portworx-install-with-kubernetes/operate-and-maintain-on-kubernetes/troubleshooting/unlink-a-portworx-essentials-cluster/
- viewing you spec (in the actions menu of your spec)
- getting the USERID in the first line of the shown k8s installation # SOURCE:https://install.portworx.com/?...&user=*USERID*&...

#### PORTWORX_VERSION
The version of Portworx to install. Setting this to `latest` makes use of the latest version. Setting this or [PORTWORX](#portworx) to `0` or `false` disables kubernetes installation.
Default is latest.

#### PORTWORX_CLUSTER
The name of the Portworx cluster to create.
Default is default.

#### PORTWORX_SIZE
Size in GiB of the Portworx-dedicated additional partition. A new disk of this size is to be created for each VM.
Default is 60.

#### GLUSTER
Wether to install Gluster and Heketi.
Default is false.

#### GLUSTER_VERSION
The version of GlusterFS to install. Setting this or [GLUSTER](#gluster) to `0` or `false` disables kubernetes installation.
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
The version of Traefik to install. Check tags on [Docker Hub](https://hub.docker.com/_/traefik).
Default is 2.2.

#### TRAEFIK_DB_PORT
The port at which exposing the Traefik dashoard. Set to 0 to disable.
Default is 9000.

### Nodes configuration

#### NODES
The number of nodes in the cluster (including master).
Default is 3 (minimum required for Heketi, could be 2 if setting [GLUSTER](#gluster) to 0).

#### MEM
The memory used by each worker VM (in MB)
Default is 2048.

#### CPU
The number of CPUs for worker nodes
Default is 1.

#### MASTER_MEM
The memory used by the master VM (in MB)
Default is 2048.

#### MASTER_CPU
The number of CPUs for the master node
Default is 2.

#### PUBLIC_ROOT_KEY
The public key used for pasphraseless ssh between node. It's the same key for each node. Should be synchronized with [PRIVATE_ROOT_KEY](#private_root_key). You're encouraged to change the default value.

#### PRIVATE_ROOT_KEY
The private key used for pasphraseless ssh between node. Should be synchronized with [PUBLIC_ROOT_KEY](#public_root_key). It's the same key for each node. You're encouraged to change the default value.

#### BOX
The image to use. It must be Debian-based. So far, only tested with bento/debian-10 and its fork fondement/k8s.
Default is fondement/k8s.

#### BOX_URL
The url of the image to use. It must be consistent with [BOX](#box).
Default is false.

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
Whether to upgrade OS. In case OS is actually upgraded, restart cluster with `vagrant halt;vagrant up`.
Default is false.

#### SCP
Whether to install the [vagrant-scp](https://github.com/invernizzi/vagrant-scp) plugin.
Default is true.
