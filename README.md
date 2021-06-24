This branch is using K3s as the Kubernetes distribution and [Longhorn](https://longhorn.io/) as a storage provider.
Check other branches for other providers.

# vagrant-kubernetes
Starting up a Kubernetes cluster with Vagrant and VirtualBox.

```
vagrant box update # can fail safely
vagrant up
# Now you can login
vagrant ssh
# You are no able to play with kubectl, docker, helm
kubectl get pods
```

Created nodes are k3s01 (master), k3s02, k3s03 and so on (depends on [NODES](#nodes) and [PREFIX](#prefix) variables). Kubernetes Dashboard with admin rigths is available at http://192.168.98.100:8001/

Cluster can merly be stopped by issuing `vagrant halt` and later restarted with `vagrant up` (with same env vars!).

[PersistentVolumeClaims](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#persistentvolumeclaims) are provisionned by [Longhorn](https://longhorn.io/). Longhorn dashboard is available at http://192.168.98.100:8002. Check other branches to change storage provider or use Kubeadm.

[Ingresses](https://kubernetes.io/docs/concepts/services-networking/ingress/) are served by [Traefik](https://docs.traefik.io/providers/kubernetes-ingress/) on port 80. The traefik dashboard is available at http://192.168.98.100:9000/.

## Testing

Invoke `kubectl apply -f https://raw.githubusercontent.com/fondemen/vagrant-kubernetes/k3s/nginx-test-file.yml`. Within the next minute, you should find a [`nginx.local/` router](http://192.168.98.100/dashboard/#/http/routers/nginx-ingress-default-nginx-local@kubernetes) associated to a [servce with two backends](http://192.168.98.100/dashboard/#/http/services/default-nginx-service-80@kubernetes). `curl -H 'Host: nginx.local' 192.168.98.100` should return a 403 (as no file exists to be served).

To load a file, `kubectl exec $(kubectl get pods -l=run=nginx -o jsonpath="{.items[0].metadata.name}") -- sh -c 'echo "Hello!" >/usr/share/nginx/html/index.html'` will create an index.html file with `Hello!` as content in the volume which is shared betwxeen both nginx pods. Now `curl -H 'Host: nginx.local' 192.168.98.100` should serve you `Hello!`.

## Remote access

To use [kubectl](https://kubernetes.io/fr/docs/reference/kubectl/overview/) directly from the host machine, do `vagrant ssh -c 'cat ~/.kube/config' > kubeconfig; export KUBECONFIG="$PWD/kubeconfig"`. Note that the exported config supplies full admin rights to the cluster.

Dashboards ([Kubernetes](#k8s_db_port), [Traefik](#traefik_db_port) and [Longhorn](#longhorn_db_port)) can be exposed *unsecured* on the host machine by setting the EXPOSE_DB_PORTS env var to true *before* firing up the `vagrant up` or another `vagrant provision` in case the cluster already exists.

## Configuration

Configuration is performed using environment variables:

#### K8S_IMAGE
Changes default values for some of the following environment variables (such as [K8S_VERSION](#k8s_version)) so that they match latest [available dedicated image](https://app.vagrantup.com/fondement/boxes/k3s). State `true` or `1` to enable.
Default is false.

### Cluster configuration

#### K8S_VERSION
The version of Kubernetes to install. Keep it in sync with [DOCKER_VERSION](#docker_version) (see [containner runtime installation](https://kubernetes.io/docs/setup/production-environment/container-runtimes/#docker)). Set to latest to get the latest version, or 0 to disable.
Default is 1.20.

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
The version of calico to use. Set to latest to get the latest version.
Default is latest.

#### HELM_VERSION
The version of [Helm](https://helm.sh/) to install. Check https://github.com/helm/helm/releases. Must be above 3.
Default is 3.5.3.

#### MASTER_CRI
The container runtime to use for the master. Possible values are containerd or docker. Define docker in case you need to build images on the first node.
Default is containerd.

### Storage configuration

#### LONGHORN_VERSION
The version of Longhorn to use. Set to latest to get the latest version.
Default is latest.

#### LONGHORN_REPLICAS
The default number of replicas for Longhorn volumes.
Default is 3 with 1 as a minimum and [NODES](#nodes)-1 as a maximum.

#### LONGHORN_DB_PORT
The port at which exposing the Longhorn Dashboard. Traefik must be [enabled](#traefik) for the dashboard to be visible. Set to 0 to disable.
Default is 8002.

### Ingress configuration

#### TRAEFIK
The version of Traefik to install. Check tags on [Docker Hub](https://hub.docker.com/_/traefik). Set to latest to get the latest version.
Default is latest.

#### TRAEFIK_DB_PORT
The port at which exposing the Traefik dashoard. Set to 0 to disable.
Default is 9000.

### Nodes configuration

#### NODES
The number of nodes in the cluster (including master).
Default is 3.

#### MEM
The memory used by each node (in MB)
Default is 1536.

#### CPU
The number of CPUs for nodes. Minimum is 2.
Default is 2.

#### PUBLIC_ROOT_KEY
The public key used for pasphraseless ssh between node. It's the same key for each node. Should be synchronized with [PRIVATE_ROOT_KEY](#private_root_key). You're encouraged to change the default value.

#### PRIVATE_ROOT_KEY
The private key used for pasphraseless ssh between node. Should be synchronized with [PUBLIC_ROOT_KEY](#public_root_key). It's the same key for each node. You're encouraged to change the default value.

#### BOX
The image to use. It must be Debian-based. So far, only tested with bento/debian-10 and its fork fondement/k3s.
Default is fondement/k3s.

#### BOX_URL
The url of the image to use. It must be consistent with [BOX](#box).
Default is false.

#### PREFIX
The name prefix for VMs. The final VM name is the prefix followed by VM number using 2 digits.
Default value is k8s.

#### MASTER_IP
The IP of the first node (e.g. k8s01), that is the master node. Other nodes have the same IP + their node number -1, e.g. if node 0 is 192.168.98.100, then node 3 is 192.168.98.102.
Default value is 192.168.98.100.

#### GUEST_ADDITIONS
Whether to check for VirtualBox guest additions.
Default is false.

#### UPGRADE
Whether to upgrade OS. In case OS is actually upgraded, restart cluster with `vagrant halt;vagrant up`.
Default is false.

#### SCP
Whether to install the [vagrant-scp](https://github.com/invernizzi/vagrant-scp) plugin.
Default is true.
