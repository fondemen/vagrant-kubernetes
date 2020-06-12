# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.require_version ">= 1.6.0"

def read_bool_env key, default_value = false
    key = key.to_s
    if ENV.include?(key)
      return ! (['no', 'off', 'false', '0']).include?(ENV[key].strip.downcase)
    else
      return default_value
    end
end
  
def read_env key, default_value = nil, false_value = false
    key = key.to_s
    if ENV.include?(key)
        val = ENV[key].strip
        if  (['no', 'off', 'false', '0']).include? val
            return false_value
        else
            return val
        end
    else
        return default_value
    end
end

required_plugins = []
required_plugins << 'vagrant-scp' if read_bool_env 'SCP', true

plugins_to_install = required_plugins.select { |plugin| not Vagrant.has_plugin? plugin }
if not plugins_to_install.empty?
  puts "Installing plugins: #{plugins_to_install.join(' ')}"
  if system "vagrant plugin install #{plugins_to_install.join(' ')}"
    exec "vagrant #{ARGV.join(' ')}"
  else
    abort "Installation of one or more plugins has failed. Aborting."
  end
end

memory = read_env 'MEM', '2048'
master_memory = read_env 'MASTER_MEM', '2048'
cpus = read_env 'CPU', '1'
master_cpus = read_env 'MASTER_CPU', ([cpus.to_i, 2].max).to_s # 2 CPU min for master
nodes = (read_env 'NODES', 3).to_i
raise "There should be at least one node and at most 255 while prescribed #{nodes} ; you can set up node number like this: NODES=2 vagrant up" unless nodes.is_a? Integer and nodes >= 1 and nodes <= 255

docker_version = read_env 'DOCKER_VERSION', '19.03.8' # check https://kubernetes.io/docs/setup/production-environment/container-runtimes/ and apt-cache madison docker-ce ; apt-cache madison containerd.io
docker_repo_fingerprint = read_env 'DOCKER_APT_FINGERPRINT', '0EBFCD88'

k8s_version = read_env 'K8S_VERSION', '1.18'
k8s_short_version = k8s_version.split('.').slice(0,2).join('.') if k8s_version
k8s_db_version = read_env 'K8S_DB_VERSION', 'latest'
k8s_db_port = (read_env 'K8S_DB_PORT', 8001).to_i
k8s_db_url = "https://raw.githubusercontent.com/kubernetes/dashboard/#{if k8s_db_version == "latest" then "master" else "v#{k8s_db_version}" end}/aio/deploy/alternative.yaml" if k8s_db_version

box = read_env 'BOX', if k8s_short_version && Gem::Version.new(k8s_short_version).between?(Gem::Version.new('1.17'), Gem::Version.new('1.18')) then 'fondement/k8s' else 'bento/debian-10' end # must be debian-based
box_url = read_env 'BOX_URL', false # e.g. https://svn.ensisa.uha.fr/vagrant/k8s.json
# Box-dependent
vagrant_user = read_env 'VAGRANT_USER', 'vagrant'
vagrant_group = read_env 'VAGRANT_GROUP', 'vagrant'
vagrant_home = read_env 'VAGRANT_HOME', '/home/vagrant'
upgrade = read_bool_env 'UPGRADE'

cni = (read_env 'CNI', 'calico').downcase
calico = false
flannel = false
case cni
    when 'flannel'
        flannel = true
    when 'calico'
        calico = true
    else
        raise "Please, supply a CNI provider using the CNI env var ; supported options are 'flannel' and 'calico' (while given '#{cni}')"
end
calico_version = read_env 'CALICO_VERSION', 'latest' if calico
calico_url = if calico_version then if 'latest' == calico_version then 'https://docs.projectcalico.org/manifests/calico.yaml' else "https://docs.projectcalico.org/v#{calico_version}/manifests/calico.yaml" end else nil end
calicoctl_url = if calico_version then if 'latest' == calico_version then 'https://docs.projectcalico.org/manifests/calicoctl.yaml' else "https://docs.projectcalico.org/v#{calico_version}/manifests/calicoctl.yaml" end else nil end

if read_bool_env 'GLUSTER', false
    raise "There should be at least 3 nodes in a GlusterFS cluster ; set GLUSTER env var to 0 to disable GlusterFS" unless nodes >= 3

    gluster_version = read_env 'GLUSTER_VERSION', '7'
    gluster_size = (read_env 'GLUSTER_SIZE', 60).to_i
    heketi_version = read_env 'HEKETI_VERSION', '9.0.0'
    raise "Heketi requires both Kubernetes and GlusterFS" unless k8s_version && gluster_version
    heketi_admin_secret = read_env 'HEKETI_ADMIN', "My Secret"
    heketi_secret = read_env 'HEKETI_PASSWORD', "My Secret"

    gluster_replicas = read_env 'GLUSTER_REPLICAS', '2'
else
    gluster_version = false
    heketi_version = false
end

if read_bool_env 'LINSTOR', true
    linstor_kube_version = read_env 'LINSTOR_KUBE_VERSION', "1.7.1-2" # check https://github.com/kvaps/kube-linstor/releases
    linstor_ns = read_env 'LINSTOR_NS', "linstor"
    linstor_password = read_env 'LINSTOR_PASSWORD', "linstor_supersecret_password"
    drbd_version = read_env 'LINSTOR_DRBD_DKMS_VERSION', "9.0.23-1" # check https://www.linbit.com/linbit-software-download-page-for-linstor-and-drbd-linux-driver/
    drbd_simple_version = drbd_version.split('.').slice(0,2).join('.')
    drbd_utils_version = read_env 'LINSTOR_DRBD_UTILS_VERSION', "9.13.1" # check https://www.linbit.com/linbit-software-download-page-for-linstor-and-drbd-linux-driver/
    drbd_size = (read_env 'LINSTOR_DRBD_SIZE', 60).to_i
    linstor_pg_version = read_env 'LINSTOR_PG_VERSION', "12" # check https://hub.docker.com/_/postgres?tab=description
    linstor_zfs = false # not implemented yet
else
    linstor_kube_version = false
end

if gluster_version && linstor_kube_version
  default_storage = (read_env 'DEFAULT_STORAGE', 'gluster').downcase
elsif gluster_version
  default_storage = 'gluster'
elsif linstor_kube_version
  default_storage = 'linstor'
end

# Directory root for additional vdisks for Gluster or Linstor
if (/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM) != nil
  vboxmanage_path = "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"
else
  vboxmanage_path = "VBoxManage" # Assume it's in the path
end
vdisk_root = begin `"#{vboxmanage_path}" list systemproperties`.split(/\n/).grep(/Default machine folder/).first.split(':')[1].strip rescue read_env("HOME") + "/VirtualBox VMs/" end

traefik_version = read_env 'TRAEFIK', '2.2'
traefik_db_port = (read_env 'TRAEFIK_DB_PORT', '9000').to_i

helm_version = read_env 'HELM_VERSION', '3.2.1' # check https://github.com/helm/helm/releases
tiller_namespace = read_env 'TILLER_NS', 'tiller'

raise "Traefik requires Helm to be installed" if traefik_version && !helm_version
raise "Traefik requires Helm v3+" if traefik_version && Gem::Version.new(helm_version) < Gem::Version.new('3')

host_itf = read_env 'ITF', false

leader_ip = (read_env 'MASTER_IP', "192.168.2.100").split('.').map {|nbr| nbr.to_i} # private ip ; public ip is to be set up with DHCP
hostname_prefix = read_env 'PREFIX', 'k8s'

expose_db_ports = read_bool_env 'EXPOSE_DB_PORTS', false

guest_additions = read_bool_env 'GUEST_ADDITIONS', false

public = read_bool_env 'PUBLIC', false
private = read_bool_env 'PRIVATE', true

public_itf = 'eth1' # depends on chosen box and order of interface declaration
private_itf = if public then 'eth2' else 'eth1' end # depends on chosen box
default_itf = read_env 'DEFAULT_PUBLIC_ITF', if public then public_itf else private_itf end # default gateway
internal_itf = case ENV['INTERNAL_ITF']
    when 'public'
        raise 'Cannot use public interface in case it is disabled ; state PUBLIC=yes' unless public
        public_itf
    when 'private'
        raise 'Cannot use private interface in case it is disabled ; state PRIVATE=yes' unless private
        private_itf
    when String
        ENV['ETCD_ITF'].strip
    else
        if public then public_itf else private_itf end
end # interface used for internal node communication (i.e. should it be public or private ?)
host_ip_script = "ip -4 addr list #{internal_itf} |  grep -v secondary | grep inet | sed 's/.*inet\\s*\\([0-9.]*\\).*/\\1/'"

init = read_bool_env 'INIT', true
nodes = 1 unless init

definitions = (1..nodes).map do |node_number|
    hostname = "%s%02d" % [hostname_prefix, node_number]
    ip = leader_ip.dup
    ip[-1] += node_number-1
    ip_str = ip.join('.')
    raise "Not enough addresses available for all nodes, e.g. can't assign IP #{ip_str} to #{hostname} ; lower NODES number or give another MASTER_IP" if ip[-1] > 255
    {:hostname => hostname, :ip => ip_str}
end

if public
    require 'socket'
    vagrant_host = Socket.gethostname || Socket.ip_address_list.find { |ai| ai.ipv4? && !ai.ipv4_loopback? }.ip_address
    puts "this host is #{vagrant_host}"
    require 'digest/md5' # used later for machine id generation so that dhcp returns the same IP
end

pub_key = read_env 'PUBLIC_ROOT_KEY', 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDFCEEemETfqtunwT8G2A+aaqJlXME99G0LtSk2Nd7ER1uPt54lY6uxCs+5lz6c6WXS58XPHNOOfz8F9iUgyJqOM97Dj9HOaSAdmE+xvOHa5lf8fUpeb3GhRNvp8vnwQDfKG3wdrMLUlZjqMbJnH63C/H5nwQ4LybbfLc9XtL8D7PQEGW5SbUaEmULNO46JydEUWgtGodjc6UHs0YVor8e89Up5uy5a0MGIQeB2B6y6rkVc2+aNwUka8bY3O9HuLlJmB+iYKu9IP/pVwy3Y733FRyB7XJJL4T1jsMZfjbQoyPoEGVU5EC8j8dUy+XkUfCe5dWY1wdNDG9oBbwWz1+B5'
priv_key = read_env 'PRIVATE_ROOT_KEY', '-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxQhBHphE36rbp8E/BtgPmmqiZVzBPfRtC7UpNjXexEdbj7eeJWOr
sQrPuZc+nOll0ufFzxzTjn8/BfYlIMiajjPew4/RzmkgHZhPsbzh2uZX/H1KXm9xoUTb6f
L58EA3yht8HazC1JWY6jGyZx+twvx+Z8EOC8m23y3PV7S/A+z0BBluUm1GhJlCzTuOicnR
FFoLRqHY3OlB7NGFaK/HvPVKebsuWtDBiEHgdgesuq5FXNvmjcFJGvG2NzvR7i5SZgfomC
rvSD/6VcMt2O99xUcge1ySS+E9Y7DGX420KMj6BBlVORAvI/HVMvl5FHwnuXVmNcHTQxva
AW8Fs9fgeQAAA8h6qyIHeqsiBwAAAAdzc2gtcnNhAAABAQDFCEEemETfqtunwT8G2A+aaq
JlXME99G0LtSk2Nd7ER1uPt54lY6uxCs+5lz6c6WXS58XPHNOOfz8F9iUgyJqOM97Dj9HO
aSAdmE+xvOHa5lf8fUpeb3GhRNvp8vnwQDfKG3wdrMLUlZjqMbJnH63C/H5nwQ4LybbfLc
9XtL8D7PQEGW5SbUaEmULNO46JydEUWgtGodjc6UHs0YVor8e89Up5uy5a0MGIQeB2B6y6
rkVc2+aNwUka8bY3O9HuLlJmB+iYKu9IP/pVwy3Y733FRyB7XJJL4T1jsMZfjbQoyPoEGV
U5EC8j8dUy+XkUfCe5dWY1wdNDG9oBbwWz1+B5AAAAAwEAAQAAAQEAiWQHHJFrPVgD0Qdk
rp4My01eLjYuncgKHebWdPG9g7qKcz3DrijBOTPjw3NeesYZdaaefZyJPM0oIj0QiLq5Yz
1yMYXg9ADEHz7tG3AtQZnrcqnfKNinMKA2hP0kIc512J2vv3WPafNi7LN4xoYFgXjVn/2z
kK64sQldkrf7lnzzFq7/3/hxiCKhkYd3MO3n213WmvCXnv/fogliIQUMRUov5A4Ib+VgMt
livMFssyktZUK0p8Lnq4MT8G7vsPGfOC4KNVORyvhQWL3AavdrxXjm6Ss4ycudv08ZrFuw
wvMmlZ79MpANcuc8zdZJM0qoES9PKHx8bh0EN1HitbMr3QAAAIB+NbJ8UKeFXiCnJ+IE3y
uhCteLo8jWwThQDBHoueP7cNVIsNT2c1sryKwRS576hUy0vmoNeAUhePFiFZ1hKIJjbqtz
wuZYb7TG0W2ohgxurTW7OEShhOsv17Y6APYd5G2fNQ15CX8D/Ij8QcPqtrxwUOJYaeQgod
/2+2QG5ynjDgAAAIEA9Hd5M8sxmeGkLUJmQ64Xnk4f+ClzR7JWRSjFO6YPj4c5ZpBlBxvj
mBMt/CGlMV4+29F/rWmRW0SgHNHQUUSfcqQ2tUFXMnKo5YO0vDIXV6ZSYOq7P8VFGY7qiu
WeA3gQboC1afHP2UE+JWVA/lrQK9FRYA1mVU6dH6a75OTTRN8AAACBAM5T5S3P6mZKZA2l
/DocqoOGF7w/Op6ARNOU0vl0hJhY7B8TvM97TfB6u3lpVyQhixxFChPrfj2mfFsT/HeX9I
wQ9BHtc5YfU7ePa+1XuXDfd1wDgF3lxETMcIpjKDODS7hRfFD0b/q3Hv9zWzaug4C70+pU
JMSNVvJ7sbXxrW2nAAAADnZhZ3JhbnRAazhzLTAxAQIDBA==
-----END OPENSSH PRIVATE KEY-----'

Vagrant.configure("2") do |config_all|
    # always use Vagrants insecure key
    config_all.ssh.insert_key = false
    # forward ssh agent to easily ssh into the different machines
    config_all.ssh.forward_agent = true
    config_all.vm.box = box
    config_all.vm.box_version = "0.#{k8s_short_version}" if box == 'fondement/k8s' && k8s_short_version
    begin config_all.vm.box_url = box_url if box_url rescue nil end

    config_all.vm.synced_folder ".", "/vagrant", disabled: true
    config_all.vm.synced_folder ".", "/home/vagrant/sync", disabled: true

    root_hostname = definitions[0][:hostname]
    root_ip = definitions[0][:ip]

    config_all.vm.provider :virtualbox do |vb|
        #config_all.timezone.value = :host
        vb.check_guest_additions = guest_additions
        vb.functional_vboxsf     = false
        if Vagrant.has_plugin?("vagrant-vbguest") then
            config_all.vbguest.auto_update = upgrade
        end
    end

    # Generic
    config_all.vm.provision "Aliases", :type => "shell", :name => "Setting up aliases", :inline => "
        grep -q 'alias ll=' /etc/bash.bashrc || echo 'alias ll=\"ls -alh\"' >> /etc/bash.bashrc
    "
    config_all.vm.provision "Upgrade", :type => "shell", :name => "Upgrading system", :inline => "
        export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get dist-upgrade --yes
        apt-get -y autoremove
        apt-get -y autoclean
    " if upgrade

    # Referencing all IPs in /etc/hosts
    config_all.vm.provision "Network", :type => "shell", :name => "Configuring network", :inline => "
        echo 'nameserver 8.8.8.8 8.8.4.4' > /etc/resolv.conf
        sed -i 's/^DNS=.*/DNS=8.8.8.8 8.8.4.4/' /etc/systemd/resolved.conf
        sed -i '/^127\\.\\0\\.1\\.1/d' /etc/hosts
    " if init
    definitions.each do |node|
        config_all.vm.provision "#{node[:hostname]}Access", :type => "shell", :name  => "Referencing #{node[:hostname]}", :inline => "grep -q " + node[:hostname] + " /etc/hosts || echo \"" + node[:ip] + " " + node[:hostname] + "\" >> /etc/hosts"
    end if init

    # Auto SSH
    config_all.vm.provision "SSHRootAuthorizationFile", :type => "shell", :name => 'auto ssh', :inline => "mkdir -m 0700 -p /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys"
    (1..nodes).each do |node_number|
        node_name = definitions[node_number-1][:hostname]
        config_all.vm.provision "SSHRootAuthorizationFrom#{node_name}", :type => "shell", :name => "auto ssh from #{node_name}", :inline => "
            grep -q 'root@#{node_name}' /root/.ssh/authorized_keys || echo 'ssh-rsa #{pub_key} root@#{node_name}' >> /root/.ssh/authorized_keys
        "
    end if init

    # Docker Installation
    if docker_version
        config_all.vm.provision "DockerInstall", :type => "shell", :name => 'Installing Docker', :inline => "
            if ! which docker >/dev/null; then
                export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
                export DEBIAN_FRONTEND=noninteractive
                apt-get update
                apt-get install --yes apt-transport-https ca-certificates curl gnupg2 software-properties-common
                DIST=$(lsb_release -i -s  | tr '[:upper:]' '[:lower:]')
                curl -fsSL https://download.docker.com/linux/$DIST/gpg | apt-key add -
                apt-key fingerprint #{docker_repo_fingerprint}
                add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/$DIST $(lsb_release -cs) stable\"
                apt-get update
                DOCKER_VERSION=$(apt-cache madison docker-ce | grep '#{docker_version}' | head -1 | awk '{print $3}')
                echo \"Installing Docker $DOCKER_VERSION\"
                apt-get install --yes docker-ce=$DOCKER_VERSION docker-ce-cli=$DOCKER_VERSION containerd.io
                apt-mark hold docker-ce docker-ce-cli containerd.io
            fi
            if [ ! -f /etc/docker/daemon.json ]; then
                cat > /etc/docker/daemon.json <<EOF
{
    \"exec-opts\": [\"native.cgroupdriver=systemd\"],
    \"log-driver\": \"json-file\",
    \"log-opts\": {
        \"max-size\": \"100m\"
    },
    \"storage-driver\": \"overlay2\"
}
EOF
                mkdir -p /etc/systemd/system/docker.service.d
                systemctl daemon-reload
                systemctl restart docker
                echo \"Docker daemon restarted\"
            fi
            usermod -aG docker vagrant
            "
    end

    # Kubernetes installation
    if k8s_version
        raise "Cannot install Kubernetes without Docker" unless docker_version
        config_all.vm.provision "K8SInstall", type: "shell", name: 'Installing Kubernetes', inline: "
            if ! which kubeadm >/dev/null; then
                export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
                export DEBIAN_FRONTEND=noninteractive
                swapoff -a;sed -i '/swap/d' /etc/fstab
                update-alternatives --set iptables /usr/sbin/iptables-legacy
                update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
                update-alternatives --set arptables /usr/sbin/arptables-legacy
                update-alternatives --set ebtables /usr/sbin/ebtables-legacy
                curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
                echo 'deb https://apt.kubernetes.io/ kubernetes-xenial main' >/etc/apt/sources.list.d/kubernetes.list
                apt-get update
                K8S_VERSION=$(apt-cache madison kubeadm | grep '#{k8s_version}' | head -1 | awk '{print $3}')
                apt-get install --yes ebtables ethtool kubelet=$K8S_VERSION kubeadm=$K8S_VERSION kubectl=$K8S_VERSION
                echo \"Installing Kubernetes $K8S_VERSION\"
                update-alternatives --set iptables /usr/sbin/iptables-legacy
                update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
                update-alternatives --set arptables /usr/sbin/arptables-legacy
                update-alternatives --set ebtables /usr/sbin/ebtables-legacy
                apt-mark hold kubelet kubeadm kubectl
            fi
            [ -f /etc/bash_completion.d/kubectl ] || kubectl completion bash >/etc/bash_completion.d/kubectl
            grep -q 'alias k=' /etc/bash.bashrc || echo 'alias k=kubectl' >> /etc/bash.bashrc
            grep -q 'complete -F __start_kubectl k' /etc/bash.bashrc || echo 'complete -F __start_kubectl k' >> /etc/bash.bashrc
            "
        config_all.vm.provision "K8SImages", type: "shell", name: 'Downloading Kubernetes images', inline: "
            kubeadm config images pull
        " unless init

        config_all.vm.provision "K8SDashboardImages", type: "shell", name: 'Downloading Kubernetes Dashboard images', inline: "
            curl -sL #{k8s_db_url} | grep 'image:' | sed 's/image://' | xargs -I IMG docker image pull -q IMG
        " unless init
    end

    config_all.vm.provision "CalicoDownload", type: "shell", name: "Downloading Calico #{calico_version} binaries", inline: "
        curl -sL #{calico_url} | grep 'image:' | sed 's/image://' | xargs -I IMG docker image pull -q IMG
        curl -sL #{calicoctl_url} | grep 'image:' | sed 's/image://' | xargs -I IMG docker image pull -q IMG
    " if calico_version && !init

    # Gluster installation
    if gluster_version
        config_all.vm.provision "GlusterInstall", type: "shell", name: 'Installing GlusterFS', inline: "
            if ! which gluster >/dev/null; then
                export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
                export DEBIAN_FRONTEND=noninteractive
                curl -s https://download.gluster.org/pub/gluster/glusterfs/#{gluster_version}/rsa.pub | apt-key add -
                DEBID=$(grep 'VERSION_ID=' /etc/os-release | cut -d '=' -f 2 | tr -d '\"')
                DEBVER=$(grep 'VERSION=' /etc/os-release | grep -Eo '[a-z]+')
                DEBARCH=$(dpkg --print-architecture)
                echo \"deb https://download.gluster.org/pub/gluster/glusterfs/#{gluster_version}/LATEST/Debian/${DEBID}/${DEBARCH}/apt ${DEBVER} main\" > /etc/apt/sources.list.d/gluster.list
                apt-get update
                apt-get install --yes glusterfs-server glusterfs-client xfsprogs
            fi
            systemctl start glusterd
            systemctl enable glusterd
        "

        # Heketi installation
        if k8s_version && heketi_version
            config_all.vm.provision "HeketiUser", type: "shell", name: 'Authorizing Heketi', inline: "
                useradd -m heketi
                grep -q 'Defaults:heketi !requiretty' /etc/sudoers || echo 'Defaults:heketi !requiretty' >> /etc/sudoers
                grep -q 'heketi ALL=' /etc/sudoers || echo 'heketi ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers
            "
            config_all.vm.provision "HeketiBinaries", type: "shell", name: 'Downloading Heketi binaries', inline: "
                export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
                export DEBIAN_FRONTEND=noninteractive
                if [ ! -x /usr/local/bin/heketi-cli ]; then
                    apt-get install --yes lvm2
                    echo 'Downloading Heketi binaries' ; curl -fsSL --progress-bar https://github.com/heketi/heketi/releases/download/v#{heketi_version}/heketi-v#{heketi_version}.linux.amd64.tar.gz | tar xz
                    mv ./heketi/heketi /usr/local/bin/
                    mv ./heketi/heketi-cli /usr/local/bin/
                fi
            " unless init
        end

        config_all.vm.provision "HelmInstall", :type => "shell", :name => "Installing Helm #{helm_version}", :inline => "
            which helm >/dev/null 2>&1 ||
                ( echo \"Downloading and installing Helm #{helm_version}\"
                curl -fsSL https://get.helm.sh/helm-v#{helm_version}-linux-amd64.tar.gz | tar xz && \\
                mv linux-amd64/helm /usr/local/bin && \\
                rm -rf linux-amd64 && \\
                [ -f /etc/bash_completion.d/helm ] || curl -Lsf https://raw.githubusercontent.com/helm/helm/v#{helm_version}/scripts/completions.bash > /etc/bash_completion.d/helm )
        " if helm_version && !init

        config_all.vm.provision "TraefikDownload", :type => "shell", :name => "Downloading Taefik #{traefik_version} binaries", :inline => "
            docker image pull -q traefik:#{traefik_version}
        " if traefik_version && !init
    end

    # Helm installation
    config_all.vm.provision "HelmInstall", :type => "shell", :name => "Installing Helm #{helm_version}", :inline => "
        which helm >/dev/null 2>&1 ||
            ( echo \"Downloading and installing Helm #{helm_version}\"
            curl -fsSL https://get.helm.sh/helm-v#{helm_version}-linux-amd64.tar.gz | tar xz && \\
            mv linux-amd64/helm /usr/local/bin && \\
            rm -rf linux-amd64 && \\
            [ -f /etc/bash_completion.d/helm ] || curl -Lsf https://raw.githubusercontent.com/helm/helm/v#{helm_version}/scripts/completions.bash > /etc/bash_completion.d/helm )
    " unless init

    # Linstor / DRBBD installation
    if linstor_kube_version

        config_all.vm.provision "LinstorDownload", :type => "shell", :name => "Downloading Linstor", :inline => "
            [ -d kube-linstor-#{linstor_kube_version} ] || curl -sL https://github.com/kvaps/kube-linstor/archive/v#{linstor_kube_version}.tar.gz | tar -xz
            K8S_VERSION=$(apt-cache madison kubeadm | grep '1.18' | head -1 | awk '{print $3}' | cut -d- -f1)
            helm template linstor kube-linstor-#{linstor_kube_version}/helm/kube-linstor/ -set storkScheduler.image.tag=v$K8S_VERSION | grep 'image:' | sed 's/image://' | xargs -I IMG docker image pull -q IMG
            docker pull -q postgres:#{linstor_pg_version}
        " unless init

        config_all.vm.provision "DRBDInstall", :type => "shell", :name => "Installing DRBD kernel module", :inline => "
            export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
            export DEBIAN_FRONTEND=noninteractive
            lsmod | grep -i drbd 1>/dev/null 2>&1 || (
                mkdir drbd
                cd drbd
                dpkg-query -S drbd-utils >/dev/null || (
                    [ -f drbd-utils_#{drbd_utils_version}-1_amd64.deb ] || (
                        [ -d drbd-utils-#{drbd_utils_version} ] || (
                            curl -sL https://github.com/LINBIT/drbd-utils/archive/v#{drbd_utils_version}.tar.gz | tar -xz
                            curl -sL https://www.linbit.com/downloads/drbd/utils/drbd-utils-#{drbd_utils_version}.tar.gz | tar -xz
                        )
                        cd drbd-utils-#{drbd_utils_version}
                        apt-get install -y dh-systemd docbook-xsl flex xsltproc po4a
                        ./autogen.sh
                        dpkg-buildpackage -rfakeroot -b -uc
                        cd ..
                    )
                    dpkg -i drbd-utils_#{drbd_utils_version}-1_amd64.deb
                )
                [ -f drbd-dkms_#{drbd_version}_all.deb ] || (
                    echo 'DRDB kernel module has to be compiled ; please, be patient'
                    [ -d drbd-#{drbd_version} ] || curl -sL https://www.linbit.com/downloads/drbd/#{drbd_simple_version}/drbd-#{drbd_version}.tar.gz | tar -xz
                    [ -d drdb-#{drbd_version}/debian ] || (
                        curl -sL https://github.com/LINBIT/drbd/archive/drbd-#{drbd_version}.tar.gz | tar -xz
                        mv drbd-drbd-#{drbd_version}/debian drbd-#{drbd_version}/debian
                        rm -rf drbd-drbd-#{drbd_version}
                    )
                    cd drbd-#{drbd_version}
                    # check https://dev.tranquil.it/wiki/Xenserver_-_Cr%C3%A9er_des_paquets_Debian_drbd9
                    make
                    make clean
                    apt-get install -y debhelper
                    dpkg-buildpackage -rfakeroot -b -uc
                    cd ..
                )
                dpkg -i drbd-dkms_#{drbd_version}_all.deb
                cd ..
                rm -rf drbd

                #apt-get purge -y docbook-xsl flex xsltproc po4a debhelper
                #apt-get autoremove -y

                modprobe drbd
            )
            grep -q drbd /etc/modules-load.d/modules.conf  || echo drbd >> /etc/modules-load.d/modules.conf 
        "
        config_all.vm.provision "ZFSInstall", :type => "shell", :name => "Installing ZFS kernel module", :inline => "
            lsmod | grep -qi zfs || (
                export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
                export DEBIAN_FRONTEND=noninteractive
                grep -q contrib /etc/apt/sources.list || sed -i \"s#$(lsb_release -cs) main#$(lsb_release -cs) main contrib#g\" /etc/apt/sources.list
                grep -q backports /etc/apt/sources.list || (
                    echo \"deb http://deb.debian.org/debian $(lsb_release -cs)-backports main\" >> /etc/apt/sources.list
                )
                apt-get update 
                apt-get install -y linux-headers-`uname -r`
                echo 'Installing ZFS ; this might take a while, be patient...'
                apt-get install -y -t $(lsb_release -cs)-backports dkms spl-dkms
                echo 'Installing ZFS ; this might take a while, be patient...'
                apt-get install -y -t $(lsb_release -cs)-backports zfs-dkms zfsutils-linux || /bin/true
                modprobe zfs
                grep -q zfs /etc/modules-load.d/modules.conf  || echo zfs >> /etc/modules-load.d/modules.conf 
            )
        " if linstor_zfs

    end
        
    (1..nodes).each do |node_number|
        definition = definitions[node_number-1]
        hostname = definition[:hostname]
        ip = definition[:ip]
        master = node_number == 1

        config_all.vm.define hostname, primary: node_number == 1 do |config|
            config.vm.hostname = hostname
            config.vm.provider :virtualbox do |vb, override|
                vb.memory = if master then master_memory else memory end
                vb.cpus = if master then master_cpus else cpus end
                vb.customize [
                  'modifyvm', :id,
                  '--name', hostname,
                  '--cpuexecutioncap', '100',
                  '--paravirtprovider', 'kvm',
                  '--natdnshostresolver1', 'on',
                  '--natdnsproxy1', 'on',
                ]
            end

            if public
                options = {}
                options[:use_dhcp_assigned_default_route] = true
                options[:bridge] = host_itf if host_itf
                options[:auto_config] = false
                config.vm.network "public_network", **options
                
                machine_id = (Digest::MD5.hexdigest "#{hostname} on #{vagrant_host}").upcase
                machine_id[2] = (machine_id[2].to_i(16) & 0xFE).to_s(16).upcase # generated MAC must not be multicast
                machine_mac = "#{machine_id[1, 2]}:#{machine_id[3, 2]}:#{machine_id[5, 2]}:#{machine_id[7, 2]}:#{machine_id[9, 2]}:#{machine_id[11, 2]}"
                
                config.vm.provider :virtualbox do |vb, override|
                    vb.customize [
                        'modifyvm', :id,
                        '--macaddress2', "#{machine_mac.delete ':'}",
                    ]
                end
            end # public itf

            config.vm.network :private_network, ip: ip

            # Same SSH keys for everyone
            config.vm.provision "RootKey", :type => "shell", :name => 'Installing SSH root key', :inline => "
                mkdir -m 0700 -p /root/.ssh; echo '#{priv_key}' > /root/.ssh/id_rsa; echo 'ssh-rsa #{pub_key} root@#{hostname}' > /root/.ssh/id_rsa.pub ; chmod 600 /root/.ssh/id_rsa
                ssh -o StrictHostKeyChecking=no #{root_hostname} 'ssh-keyscan #{hostname} >> /root/.ssh/known_hosts'
            "

            if k8s_version
                config.vm.provision "K8SNodeIP", type: "shell", name: 'Setting up Kubernetes node IP', inline: "
                    grep -q 1 /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo 'net.bridge.bridge-nf-call-iptables = 1' >> /etc/sysctl.conf && sysctl -p /etc/sysctl.conf
                    if [ ! -f /etc/default/kubelet ]; then
                        echo \'KUBELET_EXTRA_ARGS=\"--node-ip=#{ip}\" --cni-bin-dir=/opt/cni/bin,/usr/libexec/cni' > /etc/default/kubelet;
                        systemctl daemon-reload
                        systemctl restart kubelet
                    fi
                    "

                if master
                    # Initializing K8s
                    cidr = if flannel then '10.244.0.0/16' elsif calico then '192.168.0.0/16' else raise "Undefined CNI provider (try using CIDR env var)" end

                    config.vm.provision "K8SInit", type: "shell", name: 'Initializing the Kubernetes cluster', inline: "
                        if [ ! -f /etc/kubernetes/admin.conf ]; then echo 'Initializing Kubernetes' ; kubeadm init --apiserver-advertise-address=#{root_ip} --pod-network-cidr=#{cidr} #{if k8s_version.split('.').length > 2 then "--kubernetes-version #{k8s_version}" else '' end} | tee /root/k8sjoin.txt; fi
                        if [ ! -d $HOME/.kube ]; then mkdir -p $HOME/.kube ; cp -f -i /etc/kubernetes/admin.conf $HOME/.kube/config ; fi
                        if [ ! -d #{vagrant_home}/.kube ]; then mkdir -p #{vagrant_home}/.kube ; cp -f -i /etc/kubernetes/admin.conf #{vagrant_home}/.kube/config ; chown #{vagrant_user}:#{vagrant_group} #{vagrant_home}/.kube/config ; fi
                        "
                    if flannel
                        config.vm.provision "Flannel", type: "shell", name: 'Setting up Flannel CNI', inline: "
                            kubectl get pods --namespace kube-system 2>/dev/null | grep -q flannel || curl -s https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml | sed '/kube-subnet-mgr/a\\ \\ \\ \\ \\ \\ \\ \\ - --iface=#{internal_itf}' | tee flannel.yml | kubectl apply -f -
                        "
                    elsif calico
                        config.vm.provision "Calico", type: "shell", name: 'Setting up Calico CNI', inline: "
                            kubectl -n kube-system get daemonsets | grep calico 2>/dev/null | grep -q calico || kubectl apply -f #{calico_url}
                        "
                        config.vm.provision "CalicoCtl", type: "shell", name: 'Setting up calicoctl', inline: "
                            kubectl -n kube-system get pod calicoctl >/dev/null 2>/dev/null || kubectl apply -f #{calicoctl_url}
                            grep -q 'alias calicoctl=' /etc/bash.bashrc || echo 'alias calicoctl=\"kubectl exec -ti -n kube-system calicoctl -- /calicoctl\"' >> /etc/bash.bashrc
                        "
                    end 

                    if nodes < 3
                        config.vm.provision "AllowPodOnMaster", type: "shell", name: 'Allowing pods to be scheduled on master node', inline: "
                            kubectl get nodes #{root_hostname} -o jsonpath='{.spec.taints}' | grep -q NoSchedule && kubectl taint node #{root_hostname} node-role.kubernetes.io/master:NoSchedule- || /bin/true
                        "
                    end

                else
                    # Joining K8s
                    config.vm.provision "K8SJoin", type: "shell", name: 'Joining the Kubernetes cluster', inline: "
                        [ -d ~/.kube ] || scp -o StrictHostKeyChecking=no -r #{root_hostname}:~/.kube .
                        [ -f /etc/kubernetes/kubelet.conf ] || kubeadm join --discovery-file .kube/config
                    "
                end

                if master && k8s_db_version && k8s_db_port && k8s_db_port > 0
                    config.vm.provision "K8SDashboard", type: "shell", name: 'Installing the Kubernetes dashboard', inline: "
                    kubectl get namespaces kubernetes-dashboard >/dev/null 2>&1 || (
                        kubectl apply -f #{k8s_db_url}
                        echo '---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
    name: kubernetes-dashboard-admin
    namespace: kubernetes-dashboard
roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: kubernetes-dashboard
    namespace: kubernetes-dashboard' | kubectl apply -f -
                    )
                    "
                end
            end # k8s

            if gluster_version
                # Additional disk for GlusterFS storage
                config.vm.provider :virtualbox do |vb|
                    vb.name = hostname
                    gluster_disk_file = File.join(vdisk_root, hostname, "gluster-#{hostname}.vdi")
                    unless File.exist?(gluster_disk_file)
                        vb.customize ['createhd', '--filename', gluster_disk_file, '--format', 'VDI', '--size', gluster_size * 1024]
                    end
                    vb.customize ['storageattach', :id, '--storagectl', 'SATA Controller', '--port', 1, '--device', 0, '--type', 'hdd', '--medium', gluster_disk_file]
                end
                config.vm.provision "GlusterPartition", type: "shell", name: 'Creating an XFS partition for Gluster', inline: "
                    [ -e /dev/sdb1 ] || cat <<EOF | fdisk /dev/sdb
n
p
1


w
EOF
                    #file -sL /dev/sdb1 | grep -q XFS || mkfs.xfs /dev/sdb1
                    #grep -q '/dev/sdb1' /etc/fstab || echo '/dev/sdb1 /export/sdb1 xfs defaults 0 0' >> /etc/fstab
                    #mkdir -p /export/sdb1 && mount -a && mkdir -p /export/sdb1/brick
                "

                unless master
                    # Joining Gluster
                    config.vm.provision "GlusterJoin", type: "shell", name: 'Joining the Gluster cluster', inline: "
                        ssh -o StrictHostKeyChecking=no #{root_hostname} 'gluster pool list' | grep -q #{hostname} || ssh #{root_hostname} 'gluster peer probe #{hostname}'
                    "
                end

                if k8s_version && heketi_version
                    if master
                        # Installing Heketi on master
                        config.vm.provision "HeketiSSHKeys", type: "shell", name: 'Creating Heketi SSH keys', inline: "
                            export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
                            export DEBIAN_FRONTEND=noninteractive
                            if [ ! -x /usr/local/bin/heketi-cli ]; then
                                apt-get install --yes lvm2
                                echo 'Downloading Heketi binaries' ; curl -fsSL --progress-bar https://github.com/heketi/heketi/releases/download/v#{heketi_version}/heketi-v#{heketi_version}.linux.amd64.tar.gz | tar xz
                                mv ./heketi/heketi /usr/local/bin/
                                mv ./heketi/heketi-cli /usr/local/bin/
                            fi
                            if [ ! -f /home/heketi/.ssh/id_rsa ]; then
                                sudo -u heketi ssh-keygen -t rsa -b 4096 -m PEM -f /home/heketi/.ssh/id_rsa -q -N \"\"
                                sed -i 's/#{hostname}/#{ip}/' /home/heketi/.ssh/id_rsa.pub
                            fi
                        "
                        config.vm.provision "HeketiInstall", type: "shell", name: 'Installing Heketi', inline: <<-EOF
                            mkdir -p /etc/heketi
                            mkdir -p /var/lib/heketi
                            chown -R heketi:heketi /var/lib/heketi
                            [ -f /etc/heketi/heketi.json ] || cat > /etc/heketi/heketi.json <<EOL
{
    "_port_comment": "Heketi Server Port Number",
    "port" : "8080",

    "_use_auth": "Enable JWT authorization. Please enable for deployment",
    "use_auth" : false,

    "_jwt" : "Private keys for access",
    "jwt" : {
        "_admin" : "Admin has access to all APIs",
        "admin" : {
            "key" : "#{heketi_admin_secret}"
        },
        "_user" : "User only has access to /volumes endpoint",
        "user" : {
            "key" : "#{heketi_secret}"
        }
    },

    "_glusterfs_comment": "GlusterFS Configuration",
    "glusterfs" : {

        "_executor_comment": "Execute plugin. Possible choices: mock, ssh",
        "executor" : "ssh",

        "_db_comment": "Database file name",
        "db" : "/var/lib/heketi/heketi.db",

        "_sshexec_comment": "SSH username and private key file information",
        "sshexec": {
            "keyfile": "/home/heketi/.ssh/id_rsa",
            "user": "heketi",
            "sudo": true,
            "port": "22",
            "fstab": "/etc/fstab",
            "backup_lvm_metadata": false,
            "debug_umount_failures": true
        },
        
        "_db_comment": "Database file name",
        "db": "/var/lib/heketi/heketi.db"
    }
}
EOL
                            [ -f /etc/systemd/system/heketi.service ] || cat > /etc/systemd/system/heketi.service <<EOL
[Unit]
Description=Heketi REST API Service
Documentation=
After=network.target

[Service]
User=heketi
Group=heketi
UMask=077
ExecStart=/usr/local/bin/heketi --config=/etc/heketi/heketi.json
Restart=on-failure

StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=heketi

[Install]
WantedBy=multi-user.target
EOL
                            if [ ! -f /etc/rsyslog.d/heketi.conf ]; then
                                cat > /etc/rsyslog.d/heketi.conf <<EOL
if \\$programname == 'heketi' then /var/log/heketi.log
& stop
EOL
                                systemctl restart rsyslog
                            fi
                            systemctl enable heketi
                            systemctl start heketi
                            CLUSTER_ID=$(heketi-cli cluster list | grep '^Id:' | head -n 1 | cut -d: -f2 | cut -d ' ' -f 1)
                            [ -n "$CLUSTER_ID" ] || heketi-cli cluster create || ( sleep 10 &&  heketi-cli cluster create )
EOF
                    end

                    config.vm.provision "HeketiAddNode", :type => "shell", :name => "Adding #{hostname} to Heketi", :inline => "
                        sudo -u heketi mkdir -p /home/heketi/.ssh/
                        sudo -u heketi touch /home/heketi/.ssh/authorized_keys
                        chmod 600 /home/heketi/.ssh/authorized_keys
                        grep -q 'heketi@#{root_ip}' /home/heketi/.ssh/authorized_keys || ssh -o StrictHostKeyChecking=no #{root_hostname} 'cat /home/heketi/.ssh/id_rsa.pub 2>/dev/null' >> /home/heketi/.ssh/authorized_keys
                        ssh root@#{root_hostname} sudo -u heketi ssh -o StrictHostKeyChecking=no #{ip} /bin/true
                        CLUSTER_ID=$(ssh root@#{root_hostname} heketi-cli cluster list | tail -n 1 | cut -d: -f2 | cut -d ' ' -f 1)
                        NODES=$(ssh root@#{root_hostname} heketi-cli node list | grep $CLUSTER_ID | awk '{print $1;}' | cut -d : -f 2)
                        NODE_ID=$(for NODE in $NODES ; do INFO=$(ssh root@#{root_hostname} heketi-cli node info $NODE); echo $INFO | grep -q #{ip} && echo $NODE; done)
                        [ -n \"$NODE_ID\" ] || ssh root@#{root_hostname} heketi-cli node list | grep -q #{ip} || ssh root@#{root_hostname} heketi-cli node add --zone=1 --cluster=$CLUSTER_ID --management-host-name=#{ip} --storage-host-name=#{ip}
                        until [ -n \"$NODE_ID\" ]; do NODES=$(ssh root@#{root_hostname} heketi-cli node list | grep $CLUSTER_ID | awk '{print $1;}' | cut -d : -f 2); NODE_ID=$(for NODE in $NODES ; do INFO=$(ssh root@#{root_hostname} heketi-cli node info $NODE); echo $INFO | grep -q #{ip} && echo $NODE; done); done
                        DEVICE_ID=$(ssh root@#{root_hostname} heketi-cli node info $NODE_ID | sed -n '/Devices:/,$p' | grep 'Id:' | awk '{print $1;}' | cut -d : -f 2)
                        [ -n \"$DEVICE_ID\" ] || ssh root@#{root_hostname} heketi-cli device add --name=/dev/sdb1 --node=$NODE_ID
                    "

                    if master
                        config.vm.provision "HeketiForK8s", :type => "shell", :name => "Setting-up Heketi for Kubernetes", :inline => <<-EOF
                            kubectl get storageclasses.storage.k8s.io 2>/dev/null | grep -q glusterfs || CLUSTER_ID=$(heketi-cli cluster list | grep '^Id:' | head -n 1 | cut -d: -f2 | cut -d ' ' -f 1) echo "---
apiVersion: v1
kind: Namespace
metadata:
    name: heketi
---
apiVersion: v1
kind: Secret
metadata:
    name: heketi-secret
    namespace: heketi
type: kubernetes.io/glusterfs
data:
    key: $(echo -n #{heketi_admin_secret} | base64)
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
    name: glusterfs
    #{if 'gluster' == default_storage then "annotations:
      storageclass.kubernetes.io/is-default-class: \"true\"" else "" end}
provisioner: kubernetes.io/glusterfs
parameters:
    resturl: \\"http://#{root_ip}:8080\\"
    clusterid: \\"$CLUSTER_ID\\"
    restauthenabled: \\"true\\"
    restuser: \\"admin\\"
    secretNamespace: heketi
    secretName: \\"heketi-secret\\"
    volumetype: \\"replicate:#{gluster_replicas}\\"" | kubectl apply -f -
EOF
                    end
                end # Heketi
            end # Gluster

            if k8s_version && helm_version
                if master
                    config.vm.provision "HelmInstall", :type => "shell", :name => "Installing Helm #{helm_version}", :inline => "
                        which helm >/dev/null 2>&1 ||
                            ( echo \"Downloading and installing Helm #{helm_version}\"
                            curl -fsSL https://get.helm.sh/helm-v#{helm_version}-linux-amd64.tar.gz | tar xz && \\
                            mv linux-amd64/helm /usr/local/bin && \\
                            rm -rf linux-amd64 && \\
                            [ -f /etc/bash_completion.d/helm ] || curl -Lsf https://raw.githubusercontent.com/helm/helm/v#{helm_version}/scripts/completions.bash > /etc/bash_completion.d/helm )
                    "
                    if Gem::Version.new(helm_version) < Gem::Version.new('3')
                        config.vm.provision "TillerInstall", :type => "shell", :name => "Installing Tiller", :inline => <<-EOF
                            echo '---
apiVersion: v1
kind: Namespace
metadata:
  name: tiller
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tiller
  namespace: tiller
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: tiller-manager
  namespace: tiller
rules:
- apiGroups: ["", "extensions", "apps"]
  resources: ["configmaps"]
  verbs: ["*"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: tiller-binding
  namespace: tiller
subjects:
- kind: ServiceAccount
  name: tiller
  namespace: tiller
roleRef:
  kind: Role
  name: tiller-manager
  apiGroup: rbac.authorization.k8s.io' | kubectl apply -f -
                            sudo -u #{vagrant_user} helm init --service-account tiller --tiller-namespace #{tiller_namespace}
                            grep -q 'alias helm=' /etc/bash.bashrc || echo 'alias helm=\"helm --tiller-namespace #{tiller_namespace}\"' >> /etc/bash.bashrc
                            sudo -u #{vagrant_user} helm repo update
                            sudo -u #{vagrant_user} helm init --upgrade
                        EOF
                    end # Tiller
                end
            end # Helm

            if linstor_kube_version

                linstor_cmd = "kubectl exec -n #{linstor_ns} linstor-linstor-controller-0 -c linstor-controller -- linstor"

                if master

                    config.vm.provision "LinstorNS", :type => "shell", :name => "Setting-up namespace for Linstor", :inline => "
                        kubectl get namespaces #{linstor_ns} > /dev/null 2>&1 || kubectl create namespace #{linstor_ns}
                    "
                    config.vm.provision "LinstorDB", :type => "shell", :name => "Setting-up database for Linstor", :inline => <<-EOF
                        kubectl -n #{linstor_ns} get svc linstor-db >/dev/null 2>&1 || echo '---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: linstor-db
  namespace: #{linstor_ns}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: linstor-db
  template:
    metadata:
      labels:
        app: linstor-db
    spec:
      volumes:
      - name: linstor-postgresql-volume
        hostPath:
          path: /var/lib/linstor/db
          type: DirectoryOrCreate
      nodeSelector:
        node-role.kubernetes.io/master: ""
      tolerations:
      - key: node-role.kubernetes.io/master
        operator: Equal
        effect: NoExecute
      - key: node-role.kubernetes.io/master
        operator: Equal
        effect: NoSchedule
      containers:
      - name: postgres
        image: postgres:#{linstor_pg_version}
        volumeMounts:
        - name: linstor-postgresql-volume
          mountPath: /var/lib/postgresql/data
        ports:
        - containerPort: 5432 
        env:
        - name: POSTGRES_DB
          value: linstor
        - name: POSTGRES_USER
          value: linstor
        - name: POSTGRES_PASSWORD
          value: #{linstor_password}
---
apiVersion: v1
kind: Service
metadata:
  name: linstor-db
  namespace: #{linstor_ns}
spec:
  type: ClusterIP
  clusterIP: None
  selector:
    app: linstor-db
  ports:
  - name: postgresql
    protocol: TCP
    port: 5432
    targetPort: 5432' | kubectl apply -f -
EOF

                    config.vm.provision "Linstor", :type => "shell", :name => "Setting-up Linstor", :inline => <<-EOF
                        [ -d kube-linstor-#{linstor_kube_version} ] || curl -sL https://github.com/kvaps/kube-linstor/archive/v#{linstor_kube_version}.tar.gz | tar -xz 
                        helm -n #{linstor_ns} status linstor 2>/dev/null | grep -q deployed || echo "
controller:
  db:
    user: linstor
    password: #{linstor_password}
    connectionUrl: jdbc:postgresql://linstor-db/linstor
  nodeSelector:
    node-role.kubernetes.io/master: \\"\\"
  tolerations: 
  - effect: NoSchedule
    key: node-role.kubernetes.io/master

ssl:
  enabled: false
stunnel:
  enabled: true
    
satellite:
  ssl:
    enabled: false
  tolerations: 
  - effect: NoSchedule
    key: node-role.kubernetes.io/master 
  - effect: NoSchedule
    key: node.kubernetes.io/unschedulable

stork:
  replicaCount: 1
  tolerations:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master 
  - effect: NoSchedule
    key: node.kubernetes.io/unschedulable
  #{if nodes < 5 then "nodeSelector:
    node-role.kubernetes.io/master: \\\"\\\"" else "" end}

storkScheduler:
  image:
    tag: v$(apt-cache madison kubeadm | grep '1.18' | head -1 | awk '{print $3}' | cut -d- -f1)
  replicaCount: 1
  tolerations:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master 
  - effect: NoSchedule
    key: node.kubernetes.io/unschedulable
  #{if nodes < 5 then "nodeSelector:
    node-role.kubernetes.io/master: \\\"\\\"" else "" end}

    
csi:
  controller:
    nodeSelector:
      node-role.kubernetes.io/master: \\"\\"
    tolerations:
    - effect: NoSchedule
      key: node-role.kubernetes.io/master 
  node:
    tolerations:
    - effect: NoSchedule
      key: node-role.kubernetes.io/master 
    - effect: NoSchedule
      key: node.kubernetes.io/unschedulable" | helm -n #{linstor_ns} upgrade --install linstor kube-linstor-#{linstor_kube_version}/helm/kube-linstor -f -
                        grep -q 'alias linstor=' /etc/bash.bashrc || echo 'alias linstor=\"#{linstor_cmd}\"' >> /etc/bash.bashrc
                        #{linstor_cmd} node list >/dev/null 2>&1 || echo "Waiting for linstor to be up and running (might take some few minutes)"
                        until #{linstor_cmd} node list >/dev/null 2>&1; do sleep 3; done
EOF
                end # master

                config.vm.provision "LinstorAddNode", :type => "shell", :name => "Adding #{hostname} to Linstor", :inline => "
                    ssh root@#{root_hostname} 'kubectl -n #{linstor_ns} get --no-headers pods -o wide | grep #{hostname} | grep linstor-satellite | grep -qi running' || (
                      echo \"Waiting for linstor to be active on this node\"
                      until ssh root@#{root_hostname} 'kubectl -n #{linstor_ns} get --no-headers pods -o wide | grep #{hostname} | grep linstor-satellite | grep -qi running'; do sleep 2; done
                    )
                    ssh root@#{root_hostname} '#{linstor_cmd} node list' | grep #{hostname} | grep -q #{ip} || (
                      ssh root@#{root_hostname} '#{linstor_cmd} node create #{hostname} #{ip}'
                      echo \"Waiting for node to be online\"
                      until ssh root@#{root_hostname} '#{linstor_cmd} node list -n #{hostname}' | grep -qi online; do sleep 2; done
                    )
                "

                drbd_disk = if gluster_version then "/dev/sdc" else "/dev/sdb" end
                drbd_disk_nr = if gluster_version then 1 else 0 end
                # Additional disk for DRBD storage
                config.vm.provider :virtualbox do |vb|
                    vb.name = hostname
                    drbd_disk_file = File.join(vdisk_root, hostname, "drbd-#{hostname}.vdi")
                    unless File.exist?(drbd_disk_file)
                        vb.customize ['createhd', '--filename', drbd_disk_file, '--format', 'VDI', '--size', drbd_size * 1024]
                    end
                    vb.customize ['storageattach', :id, '--storagectl', 'SATA Controller', '--port', 1, '--device', drbd_disk_nr, '--type', 'hdd', '--medium', drbd_disk_file]
                end
                config.vm.provision "DRBDPartition", type: "shell", name: 'Creating a partition for Linstor / DRBD', inline: "
                  pvs | grep -q #{drbd_disk} || pvcreate #{drbd_disk}
                  vgs | grep -q 'linvg' || vgcreate linvg #{drbd_disk}
                  lvs | grep -q 'linlv' || lvcreate -L #{drbd_size*1024-256}M --thinpool linlv linvg
                  ssh root@#{root_hostname} '#{linstor_cmd} storage-pool list -n #{hostname} -s default | grep -q #{hostname} || #{linstor_cmd} storage-pool create lvmthin #{hostname} default linvg/linlv'
                "

                if master
                  config.vm.provision "LinstorStorageClass", type: "shell", name: 'Creating the \'linstor\' and \'linstor-3\' Kubernetes StorageClass', inline: <<-EOF
                    echo '---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: "linstor"
  #{if 'linstor' == default_storage then "annotations:
    storageclass.kubernetes.io/is-default-class: \"true\"" else "" end}
provisioner: linstor.csi.linbit.com
parameters:
  autoPlace: "2"
  storagePool: "default"
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: "linstor-3"
  #{if 'linstor-3' == default_storage then "annotations:
    storageclass.kubernetes.io/is-default-class: \"true\"" else "" end}
provisioner: linstor.csi.linbit.com
parameters:
  autoPlace: "3"
  storagePool: "default"' | kubectl apply -f -
EOF
                end
            end # linstor

            if k8s_version && helm_version && traefik_version
                if master
                    config.vm.provision "TraefikIngress", :type => "shell", :name => "Setting-up Traefik as an Ingress controller", :inline => <<-EOF
                        helm repo list | grep -q traefik || ( helm repo add traefik https://containous.github.io/traefik-helm-chart && helm repo update )
                        kubectl get namespaces traefik > /dev/null 2>&1 || kubectl create namespace traefik
                        helm -n traefik status traefik 2>/dev/null | grep -q deployed || echo '
image:
  tag: #{traefik_version}

globalArguments:
- "--global.checknewversion"
additionalArguments:
- "--providers.kubernetesingress"

service:
  enabled: false
  type: ClusterIP

ports:
  web:
    expose: false
    port: 80
    hostPort: 80
  #{if traefik_db_port && traefik_db_port > 0 then "traefik:
    expose: false
    port: #{traefik_db_port}
    hostPort: #{traefik_db_port}" end}
  #{if k8s_version && k8s_db_port && k8s_db_port > 0 then "dashboard:
    expose: false
    port: #{k8s_db_port}
    hostPort: #{k8s_db_port}" end}
  websecure:
    expose: false

securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_BIND_SERVICE]
  runAsNonRoot: false
  runAsGroup: 0
  runAsUser: 0
podSecurityContext:
  fsGroup: 0

#persistence:
#  storageClass: "glusterfs"

tolerations:
- key: node-role.kubernetes.io/master
  operator: Equal
  effect: NoExecute
- key: node-role.kubernetes.io/master
  operator: Equal
  effect: NoSchedule
nodeSelector:
  node-role.kubernetes.io/master: ""

ingressRoute:
  dashboard:
    enabled: true' | helm install -n traefik traefik traefik/traefik -f -
EOF
                    config.vm.provision "TraefikDashboard", :type => "shell", :name => "Exposing Traefik Dashboard on http://#{root_ip}:#{traefik_db_port}/", :inline => <<-EOF
                        kubectl -n traefik get ingressroute dashboard >/dev/null 2>&1 || echo '---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: dashboard
  namespace: traefik
spec:
  entryPoints:
  - traefik
  routes:
  - match: HostRegexp(`{host:.+}`)
    kind: Rule
    services:
    - name: api@internal
      kind: TraefikService' | kubectl apply -f -
EOF

                    config.vm.network "forwarded_port", guest: traefik_db_port, host: traefik_db_port if expose_db_ports
                    
                    if k8s_db_port && k8s_db_port > 0
                        config.vm.provision "KubernetesDashboard", :type => "shell", :name => "Exposing Kubernetes Dashboard on http://#{root_ip}:#{k8s_db_port}/", :inline => <<-EOF
                          kubectl -n kubernetes-dashboard get ingressroute dashboard >/dev/null 2>&1 || (
                            TOKEN=$(kubectl -n kubernetes-dashboard get secrets $(kubectl -n kubernetes-dashboard get secrets --no-headers -o custom-columns=":metadata.name" | grep kubernetes-dashboard-token-) -o jsonpath='{.data.token}' | base64 -d)
                            echo "---
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: db-bearer-token
  namespace: kubernetes-dashboard
spec:
  headers:
    customRequestHeaders:
      Authorization: \\"Bearer $TOKEN\\"
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: dashboard
  namespace: kubernetes-dashboard
spec:
  entryPoints:
    - dashboard
  routes:
    - match: HostRegexp(\\`{host:.+}\\`)
      kind: Rule
      middlewares:
        - name: db-bearer-token
          namespace: kubernetes-dashboard
      services:
        - name: kubernetes-dashboard
          namespace: kubernetes-dashboard
          kind: Service
          port: 80
" | kubectl apply -f -
                          )
EOF

                        config.vm.network "forwarded_port", guest: k8s_db_port, host: k8s_db_port if expose_db_ports
                    end # K8S Dashboard over traefik
                end
            end # Traefik
            
        end # node cfg
    end if init # node
end # config
