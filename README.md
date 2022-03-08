This branch is using [MicroK8s](https://microk8s.io) and NFS as storage provider.
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

Created nodes are k8s01 (master), k8s02 and so on (depends on [NODES](#nodes) and [PREFIX](#prefix) variables). Kubernetes Dashboard with admin rigths is available at http://192.168.60.100:8001/

Cluster can merly be stopped by issuing `vagrant halt` and later restarted with `vagrant up` (with same env vars!).

[PersistentVolumeClaims](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#persistentvolumeclaims) are provisionned by [NFS](https://microk8s.io/docs/nfs) using default storage class "nfs-csi". Actual storage is located on the first VM (k8s01) on /srv/nfs. Check other branches to chage storage provider.

[Ingresses](https://kubernetes.io/docs/concepts/services-networking/ingress/) are served by [Traefik](https://docs.traefik.io/providers/kubernetes-ingress/) on port 80. The traefik dashboard is available at http://192.168.60.100:9000/.

## Testing

Invoke `kubectl apply -f https://raw.githubusercontent.com/fondemen/vagrant-kubernetes/microk8s/nginx-test-file.yml`. Within the next minute, you should find a [`nginx.local/` router](http://192.168.60.100:9000/dashboard/#/http/routers/nginx-ingress-default-nginx-local@kubernetes) associated to a [servce with two backends](http://192.168.60.100:9000/dashboard/#/http/services/default-nginx-service-80@kubernetes). `curl -H 'Host: nginx.local' 192.168.60.100` should return a 403 (as no file exists to be served).

To load a file, `mkdir nginx-data; sudo mount -t nfs 192.168.60.100:/srv/nfs/$(kubectl get pvc test-pvc -o jsonpath='{.spec.volumeName}') nginx-data` to mount the NFS volume. Add an `index.html` file to `nginx-data`, unmount the volume by running `sudo umount nginx-data` and then `curl -H 'Host: nginx.local' 192.168.60.100` should serve you that file.

## Remote access

Dashboards ([Kubernetes](#k8s_db_port) and [Traefik](#traefik_db_port)) can be exposed *unsecured* on the host machine by setting the EXPOSE_DB_PORTS env var to true *before* firing up the `vagrant up` or another `vagrant provision` in case the cluster already exists.

## Configuration

Configuration is performed using environment variables:

#### K8S_IMAGE
Changes default values for some of the following environment variables (such as [BOX](#box) or [TRAEFIK](#traefik)) so that they match latest [available dedicated image](https://app.vagrantup.com/fondement/boxes/microk8s). State `true` or `1` to enable.
Default is false.

### Cluster configuration

#### MICROK8S_VERSION
The [channel](https://microk8s.io/docs/setting-snap-channel) of MicroK8s to install. Check . Setting this to `0` or `false` disables kubernetes installation.
Default is latest/stable.

#### K8S_DB_PORT
The port at which exposing the Kubernetes Dashboard. Traefik must be [enabled](#traefik) for the dashboard to be visible. Set to 0 to disable.
Default is 8001.

#### LOCAL_INSECURE_REGISTRIES
Coma-separated list of registries that can be accessed insecurely. Ex: `LOCAL_INSECURE_REGISTRIES`. Default is ''.

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
Default is 2.

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
The IP of the first node (e.g. k8s01), that is the master node. Other nodes have the same IP + their node number -1, e.g. if node 0 is 192.168.60.100, then node 3 is 192.168.60.102.
Default value is 192.168.60.100.

#### GUEST_ADDITIONS
Whether to check for VirtualBox guest additions.
Default is false.

#### UPGRADE
Whether to upgrade OS. In case OS is actually upgraded, restart cluster with `vagrant halt;vagrant up`.
Default is false.

#### SCP
Whether to install the [vagrant-scp](https://github.com/invernizzi/vagrant-scp) plugin.
Default is true.
