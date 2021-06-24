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

memory = read_env 'MEM', '1536'
master_memory = memory
cpus = read_env 'CPU', '2' # 2 CPU min for master + cluster needs to be equilibrated so that pods are scheduled evenly
master_cpus = cpus
nodes = (read_env 'NODES', 3).to_i
raise "There should be at least one node and at most 255 while prescribed #{nodes} ; you can set up node number like this: NODES=2 vagrant up" unless nodes.is_a? Integer and nodes >= 1 and nodes <= 255

own_image = read_bool_env 'K8S_IMAGE'

k8s_version = read_env 'K8S_VERSION', (if own_image then '1.20.5+k3s1' else '1.20' end)
if (k8s_version) then
    k8s_short_version = if k8s_version == 'latest' then 'latest' else k8s_version.split('.').slice(0,2).join('.') end
    k8s_db_version = read_env 'K8S_DB_VERSION', (if own_image then '2.2.0' else 'latest' end)
    k8s_db_port = (read_env 'K8S_DB_PORT', 8001).to_i
    k8s_db_url = "https://raw.githubusercontent.com/kubernetes/dashboard/#{if k8s_db_version == "latest" then "master" else "v#{k8s_db_version}" end}/aio/deploy/alternative.yaml" if k8s_db_version
end

docker_version = read_env 'DOCKER_VERSION', false
cri = (read_env 'MASTER_CRI', if docker_version then 'docker' else 'containerd' end).downcase
case cri
    when 'containerd'
        docker = false
    when 'docker'
        docker = true
        if ! docker_version
            docker_version = '19.03' # check https://github.com/rancher/install-docker
        end
    else
        raise "Only containerd and docker cri are supported"
end

box = read_env 'BOX', if k8s_short_version != 'latest' && Gem::Version.new(k8s_short_version).between?(Gem::Version.new('1.20'), Gem::Version.new('1.20')) then 'fondement/k3s' else 'bento/debian-10' end # must be debian-based
box_url = read_env 'BOX_URL', false # e.g. https://svn.ensisa.uha.fr/vagrant/k3s.json
# Box-dependent
vagrant_user = read_env 'VAGRANT_GUEST_USER', 'vagrant'
vagrant_group = read_env 'VAGRANT_GUEST_GROUP', 'vagrant'
vagrant_home = read_env 'VAGRANT_GUEST_HOME', '/home/vagrant'
upgrade = read_bool_env 'UPGRADE'

calico_version = read_env 'CALICO_VERSION', (if own_image then '3.18' else 'latest' end)
calico_url = if calico_version then if 'latest' == calico_version then 'https://docs.projectcalico.org/manifests/calico.yaml' else "https://docs.projectcalico.org/archive/v#{calico_version}/manifests/calico.yaml" end else nil end
calicoctl_url = if calico_version then if 'latest' == calico_version then 'https://docs.projectcalico.org/manifests/calicoctl.yaml' else "https://docs.projectcalico.org/v#{calico_version}/manifests/calicoctl.yaml" end else nil end

cni = (read_env 'CNI', if calico_version then 'calico' else 'flannel' end).downcase
calico = false
flannel = false
case cni
    when 'flannel'
        flannel = true
    when 'calico'
        calico = true
    else
        raise "Please, supply a CNI provider using the CNI env var ; supported options are 'flannel' and 'calico' (while given '#{cni}')"
end if k8s_version

longhorn_version = read_env 'LONGHORN_VERSION', (if own_image then '1.1.0' else 'latest' end)
longhorn_db_port = (read_env 'LONGHORN_DB_PORT', '8002').to_i
longhorn_replicas = (read_env 'LONGHORN_REPLICAS', [1, [nodes-1, 3].min].max).to_i

traefik_version = read_env 'TRAEFIK', (if k8s_version then (if own_image then '2.4.8' else 'latest' end) else false end)
traefik_db_port = (read_env 'TRAEFIK_DB_PORT', '9000').to_i

helm_version = read_env 'HELM_VERSION', (if k8s_version then '3.5.3' else false end) # check https://github.com/helm/helm/releases
raise "Helm is supported as from version 3" if helm_version && Gem::Version.new(helm_version) < Gem::Version.new('3')

raise "Longhorn requires Helm to be installed" if longhorn_version && !helm_version
raise "Traefik requires Helm to be installed" if traefik_version && !helm_version

host_itf = read_env 'ITF', false

leader_ip = (read_env 'MASTER_IP', "192.168.98.100").split('.').map {|nbr| nbr.to_i} # private ip ; public ip is to be set up with DHCP
hostname_prefix = read_env 'PREFIX', 'k3s'

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

control_plane_label = if helm_version && Gem::Version.new(helm_version) >= Gem::Version.new('1.20') then 'node-role.kubernetes.io/control-plane' else 'node-role.kubernetes.io/master' end

Vagrant.configure("2") do |config_all|
    # always use Vagrants insecure key
    config_all.ssh.insert_key = false
    # forward ssh agent to easily ssh into the different machines
    config_all.ssh.forward_agent = true
    config_all.vm.box = box
    config_all.vm.box_version = "0.#{k8s_short_version}" if box == 'fondement/k3s' && k8s_short_version
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

    # Kubernetes installation
    if k8s_version
        config_all.vm.provision "K3SDownload", type: "shell", name: "Downloading K3S Kubernetes #{k8s_version}", inline: "
            if ! which k3s >/dev/null 2>&1; then
                mkdir -p install
                #{if k8s_version != 'latest' then "export INSTALL_K3S_VERSION=v#{k8s_version}" end}
                [ -f ./install/k3s.sh ] || curl -sfL https://get.k3s.io >./install/k3s.sh
                mkdir -p /var/lib/rancher/k3s/agent/images/
                cd /var/lib/rancher/k3s/agent/images/
                K3S_VERSION=#{if k8s_version != 'latest' then "v#{k8s_version}" else "$(wget -SqO /dev/null https://update.k3s.io/v1-release/channels/stable  2>&1 | grep -i Location: | sed -e 's|.*/||' | sed 's|+|%2B|g')" end}
                #{if init then "[ -f k3s-airgap-images-amd64.tar ] || (wget -q https://github.com/k3s-io/k3s/releases/download/$K3S_VERSION/k3s-airgap-images-amd64.tar && echo \"K3s $K3S_VERSION images downloaded\")" end}
                [ -f /usr/local/bin/k3s ] || (wget -qO /usr/local/bin/k3s https://github.com/k3s-io/k3s/releases/download/$K3S_VERSION/k3s && echo \"K3s $K3S_VERSION downloaded\")
                chmod 755 /usr/local/bin/k3s
            fi
        "
    end

    config_all.vm.provision "HelmDownload", :type => "shell", :name => "Installing Helm #{helm_version}", :inline => "
        which helm >/dev/null 2>&1 || (
            echo \"Downloading and installing Helm #{helm_version}\" && \\
            curl -fsSL https://get.helm.sh/helm-v#{helm_version}-linux-amd64.tar.gz | tar xz && \\
            mv linux-amd64/helm /usr/local/bin && \\
            rm -rf linux-amd64 && \\
            mkdir -p /etc/bash_completion.d && \\
            ( [ -f /etc/bash_completion.d/helm ] || /usr/local/bin/helm completion bash > /etc/bash_completion.d/helm || curl -Lsf https://raw.githubusercontent.com/helm/helm/v#{helm_version}/scripts/completions.bash > /etc/bash_completion.d/helm )
        )
    " if helm_version && !init

    config_all.vm.provision "LonghornDependencies", type: "shell", name: "Downloading Longhorn dependencies", inline: "
        export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
        export DEBIAN_FRONTEND=noninteractive
        dpkg -l | grep -q open-iscsi && dpkg -l | grep -q nfs-common || (apt-get update && apt-get install -y open-iscsi nfs-common)
    " if longhorn_version
        
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

                if master

                    # Docker installation
                    if docker
                        config.vm.provision "DockerInstall", :type => "shell", :name => 'Installing Docker', :inline => "
                            which docker >/dev/null 2>&1 || curl -sfL https://releases.rancher.com/install-docker/#{docker_version}.sh | sh
                            usermod -aG docker #{vagrant_user}
                            docker images | grep -q rancher || [ -f /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar ] && docker load -i /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar
                        "
                    end

                    # Initializing K8s
                    config.vm.provision "K8SInit", type: "shell", name: 'Initializing the Kubernetes cluster', inline: "
                        export INSTALL_K3S_SKIP_DOWNLOAD=true
                        #{if k8s_version != 'latest' then "INSTALL_K3S_VERSION=\"v#{k8s_version}\"" end}
                        #{if calico then "export INSTALL_K3S_EXEC=\"--flannel-backend=none --disable-network-policy --cluster-cidr=192.168.0.0/16\"" end}
                        sh ./install/k3s.sh --node-ip #{ip} --advertise-address #{ip} --no-deploy=traefik --no-deploy=servicelb --no-deploy=local-storage --write-kubeconfig-mode=640 #{if flannel then "--flannel-iface '#{internal_itf}'" end} #{if docker then "--docker" end}
                        systemctl enable --now k3s
                        if [ ! -d $HOME/.kube ]; then mkdir -p $HOME/.kube ; cp -f -i /etc/rancher/k3s/k3s.yaml $HOME/.kube/config ; fi
                        if [ ! -d #{vagrant_home}/.kube ]; then mkdir -p #{vagrant_home}/.kube ; cp -f -i /etc/rancher/k3s/k3s.yaml #{vagrant_home}/.kube/config ; chown #{vagrant_user}:#{vagrant_group} #{vagrant_home}/.kube/config ; fi
                    "

                else
                    # Joining K8s
                    config.vm.provision "K8SJoin", type: "shell", name: 'Joining the Kubernetes cluster', inline: "
                        ssh -o StrictHostKeyChecking=no #{root_hostname} kubectl get nodes #{hostname} 2>/dev/null || [ -x /usr/local/bin/k3s-uninstall.sh ] && /usr/local/bin/k3s-uninstall.sh
                        export K3S_NODE_NAME=#{hostname}
                        export INSTALL_K3S_SKIP_DOWNLOAD=true
                        export K3S_URL=https://#{root_hostname}:6443
                        export K3S_TOKEN=$(ssh -o StrictHostKeyChecking=no #{root_hostname} cat /var/lib/rancher/k3s/server/node-token)
                        sh ./install/k3s.sh --node-ip #{ip}
                        systemctl enable --now k3s-agent
                    "
                end
                
                config.vm.provision "K3SReady", type: "shell", name: 'Waiting for Kubernetes node to be ready', inline: "
                    until ssh -o StrictHostKeyChecking=no #{root_hostname} kubectl get nodes #{hostname} 2>/dev/null | grep -iq Ready; do sleep 3; done;
                "

                config.vm.provision "K8SCmds", type: "shell", name: 'Configuring tools', inline: "
                    until which kubectl >/dev/null 2>&1; do sleep 1; done
                    mkdir -p /etc/bash_completion.d
                    [ -f /etc/bash_completion.d/kubectl ] || kubectl completion bash >/etc/bash_completion.d/kubectl
                    [ -f /etc/bash_completion.d/crictl ] || crictl completion >/etc/bash_completion.d/crictl
                    grep -q 'alias k=' /etc/bash.bashrc || echo 'alias k=kubectl' >> /etc/bash.bashrc
                    grep -q 'complete -F __start_kubectl k' /etc/bash.bashrc || echo 'complete -F __start_kubectl k' >> /etc/bash.bashrc

                    grep -q 'alias crictl=' #{vagrant_home}/.bashrc || echo 'alias crictl=\"sudo crictl\"' >> #{vagrant_home}/.bashrc

                    # chmod -R g:+r /etc/rancher/k3s
                    groups #{vagrant_user} | grep -q root || usermod -aG root #{vagrant_user}

                    [ -f /etc/profile.d/k3s_env.sh ] && grep -q KUBECONFIG /etc/profile.d/k3s_env.sh || echo \"export KUBECONFIG=/etc/rancher/k3s/k3s.yaml\" >> /etc/profile.d/k3s_env.sh
                    chmod +x /etc/profile.d/k3s_env.sh
                "
                    
                config.vm.provision "Calico", type: "shell", name: 'Setting up Calico CNI', inline: "
                    kubectl -n kube-system get daemonsets | grep calico 2>/dev/null | grep -q calico || kubectl apply -f #{calico_url}
                " if calico_version && master

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

            if k8s_version && helm_version && master
                config.vm.provision "HelmInstall", :type => "shell", :name => "Installing Helm #{helm_version}", :inline => "
                    which helm >/dev/null 2>&1 || (
                        echo \"Downloading and installing Helm #{helm_version}\" && \\
                        curl -fsSL https://get.helm.sh/helm-v#{helm_version}-linux-amd64.tar.gz | tar xz && \\
                        mv linux-amd64/helm /usr/local/bin && \\
                        rm -rf linux-amd64 && \\
                        mkdir -p /etc/bash_completion.d && \\
                        ( [ -f /etc/bash_completion.d/helm ] || /usr/local/bin/helm completion bash > /etc/bash_completion.d/helm || curl -Lsf https://raw.githubusercontent.com/helm/helm/v#{helm_version}/scripts/completions.bash > /etc/bash_completion.d/helm )
                    )
                "
            end # Helm

            if k8s_version && helm_version && longhorn_version && master
                config.vm.provision "LonghornInstall", :type => "shell", :name => "Installing Longhorn #{longhorn_version}", :inline => "
                    helm repo list | grep -q longhorn || ( helm repo add longhorn https://charts.longhorn.io && helm repo update )
                    kubectl get ns longhorn-system 2>/dev/null | grep -q longhorn-system 2>&1 || (kubectl create ns longhorn-system && helm -n longhorn-system install longhorn #{if longhorn_version != 'latest' then "--version #{longhorn_version}" end} longhorn/longhorn --set persistence.defaultClassReplicaCount=\"#{longhorn_replicas}\")
                "
            end # longhorn

            if k8s_version && helm_version && traefik_version
                if master
                    config.vm.provision "TraefikIngress", :type => "shell", :name => "Setting-up Traefik as an Ingress controller", :inline => <<-EOF
                        export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
                        helm repo list | grep -q traefik || ( helm repo add traefik https://helm.traefik.io/traefik && helm repo update )
                        kubectl get namespaces traefik > /dev/null 2>&1 || kubectl create namespace traefik
                        kubectl get ingressclasses.networking.k8s.io > /dev/null 2>&1 && ( kubectl get ingressclasses.networking.k8s.io traefik-lb >/dev/null 2>&1 || echo '
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata: 
  name: traefik
  annotations:
    ingressclass.kubernetes.io/is-default-class: "true"
spec:
  controller: traefik.io/ingress-controller' | kubectl apply -f - )
                        helm -n traefik status traefik 2>/dev/null | grep -q deployed || echo '
#{if 'latest' == traefik_version then '' else "image:
  tag: \"#{traefik_version}\"" end}

globalArguments:
- "--global.checknewversion"
additionalArguments:
- "--providers.kubernetesingress"
- "--providers.kubernetesingress.ingressclass=traefik"

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
  #{if longhorn_version && longhorn_db_port && longhorn_db_port > 0 then "longhorn:
    expose: false
    port: #{longhorn_db_port}
    hostPort: #{longhorn_db_port}" end}
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
- key: node-role.kubernetes.io/control-plane
  operator: Equal
  effect: NoExecute
- key: node-role.kubernetes.io/control-plane
  operator: Equal
  effect: NoSchedule
nodeSelector:
  #{control_plane_label}: "true"

ingressRoute:
  dashboard:
    enabled: true' | helm install -n traefik traefik traefik/traefik -f -
EOF
                    config.vm.provision "TraefikDashboard", :type => "shell", :name => "Exposing Traefik Dashboard on http://#{root_ip}:#{traefik_db_port}/", :inline => <<-EOF
                        export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
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


                    if longhorn_version && longhorn_db_port && longhorn_db_port > 0
                        config.vm.provision "LonghornDashboard", :type => "shell", :name => "Exposing Longhorn Dashboard on http://#{root_ip}:#{longhorn_db_port}/", :inline => <<-EOF
                          kubectl -n longhorn-system get ingressroute dashboard >/dev/null 2>&1 || (
                            echo "
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: dashboard
  namespace: longhorn-system
spec:
  entryPoints:
    - longhorn
  routes:
    - match: HostRegexp(\\`{host:.+}\\`)
      kind: Rule
      services:
        - name: longhorn-frontend
          namespace: longhorn-system
          kind: Service
          port: 80
" | kubectl apply -f -
                          )
EOF

                        config.vm.network "forwarded_port", guest: longhorn_db_port, host: traefik_db_port if expose_db_ports
                    end # Longhorn Dashboard over traefik
                end
            end # Traefik

            

            if read_bool_env 'BACKUP' && master
                config.vm.provision "ImageBackup", :type => "shell", :name => "Exporting necessary images", :inline => "
                    apt install docker.io
                    ctr images ls -q | grep -v 'sha256:' > images.txt
                    cat images.txt | xargs -I IMG sudo docker pull IMG
                    rm -f /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar
                    docker save $(cat images.txt) -o /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar
                    apt purge docker.io
                "
            end # backup
            
        end # node cfg
    end if init # node
end # config
