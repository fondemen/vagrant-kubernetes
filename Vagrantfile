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
nodes = (read_env 'NODES', 2).to_i
raise "There should be at least one node and at most 255 while prescribed #{nodes} ; you can set up node number like this: NODES=2 vagrant up" unless nodes.is_a? Integer and nodes >= 1 and nodes <= 255

locale = (read_env "LC_ALL", "fr_FR").split('.')[0]

own_image = read_bool_env 'K8S_IMAGE'

µk8s_version = read_env 'MICROK8S_VERSION', 'latest/stable'

k8s_db_port = (read_env 'K8S_DB_PORT', 8001).to_i

box = read_env 'BOX', if own_image then 'fondement/microk8s' else 'bento/debian-11' end # must be debian-based
box_url = read_env 'BOX_URL', false # e.g. https://svn.ensisa.uha.fr/bd/vg/microk8s.json
# Box-dependent
vagrant_user = read_env 'VAGRANT_GUEST_USER', 'vagrant'
vagrant_group = read_env 'VAGRANT_GUEST_GROUP', 'vagrant'
vagrant_home = read_env 'VAGRANT_GUEST_HOME', '/home/vagrant'
upgrade = read_bool_env 'UPGRADE'

traefik_version = read_env 'TRAEFIK', (if µk8s_version then (if own_image then '2.6.1' else 'latest' end) else false end)
traefik_db_port = (read_env 'TRAEFIK_DB_PORT', '9000').to_i

host_itf = read_env 'ITF', false

leader_ip = (read_env 'MASTER_IP', "192.168.60.100").split('.').map {|nbr| nbr.to_i} # private ip ; public ip is to be set up with DHCP
hostname_prefix = read_env 'PREFIX', 'k8s'

expose_db_ports = read_bool_env 'EXPOSE_DB_PORTS', false

guest_additions = read_bool_env 'GUEST_ADDITIONS', false

local_insecure_regs = (read_env 'LOCAL_INSECURE_REGISTRIES', "").split(",").map {|r| r.strip}

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

    config_all.vm.provision "Setting locale", :name => "locale", :type => "shell", :inline => "
      if [ $(localectl status | grep LANG | cut -f2 -d= | cut -d. -f1) != \"#{locale}\" ]; then
        sed -i 's/^#\\s*#{locale}.UTF-8/#{locale}.UTF-8/' /etc/locale.gen;
        locale-gen && localectl set-locale LANG=#{locale}.UTF-8
      fi
    "

    # Referencing all IPs in /etc/hosts
    config_all.vm.provision "Network", :type => "shell", :name => "Configuring network", :inline => "
        sed -i '/^127\\.\\0\\.[^0]\\.1/d' /etc/hosts
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

    if µk8s_version

      config_all.vm.provision "SnapInstall", :type => "shell", :name => 'Installing Snap', :inline => "
        export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
        export DEBIAN_FRONTEND=noninteractive
        which snap >/dev/null 2>&1 || ( apt-get update && apt-get install -y snapd && snap install core )
      "

      config_all.vm.provision "MicroK8sDownload", :type => "shell", :name => 'Downloading MicroK8s', :inline => "
        export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
        export DEBIAN_FRONTEND=noninteractive
        if ! snap list microk8s >/dev/null 2>&1; then
          if ! ls microk8s_*.assert >/dev/null 2>&1; then
            echo \"Downloading MicroK8s #{µk8s_version}\"
            snap download microk8s --channel=#{µk8s_version}
            snap ack $(ls microk8s_*.assert)
          fi
        fi
      "

      config_all.vm.provision "MicroK8sInstall", :type => "shell", :name => 'Installing MicroK8s', :inline => "
        export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
        export DEBIAN_FRONTEND=noninteractive
        if ls microk8s_*.assert >/dev/null 2>&1; then
          snap ack $(ls microk8s_*.assert)
          rm -f microk8s_*.assert
        fi
        if ! snap list microk8s >/dev/null 2>&1; then
          if ls microk8s_*.snap >/dev/null 2>&1; then
            echo \"Installing local MicroK8s\"
            snap install $(ls microk8s_*.snap) --classic
            rm microk8s_*.snap
            rm -rf snap
          else
            echo \"Installing MicroK8s #{µk8s_version}\"
            snap install microk8s --classic --channel=#{µk8s_version}
          fi
          while snap changes | tail +2 | grep . | grep -vq Done; do sleep 1; done
        fi
        groups vagrant | grep -q microk8s || usermod -a -G microk8s #{vagrant_user}
        [ -d #{vagrant_home}/.kube ] && chown -f -R vagrant #{vagrant_home}/.kube || /bin/true
        [ -f #{vagrant_home}/images.tar ] && microk8s ctr images import #{vagrant_home}/images.tar && rm #{vagrant_home}/images.tar || /bin/true
      " if init

      local_insecure_regs.each do |local_insecure_reg|
        config_all.vm.provision "AllowLocalRegistry#{local_insecure_reg}", :type => "shell", :name => "Allowing insecure registry at #{local_insecure_reg}", :inline => "
          if [ ! -f '/var/snap/microk8s/current/args/certs.d/#{local_insecure_reg}/hosts.toml' ]; then
            mkdir -p /var/snap/microk8s/current/args/certs.d/#{local_insecure_reg}
            echo 'server = \"http://#{local_insecure_reg}\"
[host.\"#{local_insecure_reg}\"]
capabilities = [\"pull\", \"resolve\"]' >/var/snap/microk8s/current/args/certs.d/#{local_insecure_reg}/hosts.toml
            touch microk8s.restart
          fi
        "
      end if init
      config_all.vm.provision "MicroK8sRestart", :type => "shell", :name => 'Restarting MicroK8s', :inline => "if [ -f microk8s.restart ]; then microk8s stop; microk8s start; rm -f microk8s.restart; while snap changes | tail +2 | grep . | grep -vq Done; do sleep 1; done fi" if init && local_insecure_regs.length > 0

    end

    config_all.vm.provision "NFSServer", :type => "shell", :name => 'Installing an NFS server', :inline => "
      export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
      export DEBIAN_FRONTEND=noninteractive
      dpkg -l | grep nfs-kernel-server | grep -q ^ii || apt-get install -y nfs-kernel-server
    " unless init


    config_all.vm.provision "PodmanInstall", :type => "shell", :name => "Installing podman", :inline => "
        export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
        export DEBIAN_FRONTEND=noninteractive
        if ! which podman >/dev/null 2>&1; then
            [ $(sysctl -b kernel.unprivileged_userns_clone) = '1' ] || (echo 'kernel.unprivileged_userns_clone=1' >/etc/sysctl.d/00-local-userns.conf && systemctl restart procps)
            grep -q 'buster-backports main' /etc/apt/sources.list || echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list
            [ -f /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list ] || echo 'deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_10/ /' >/etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
            apt-key export devel:kubic 2>/dev/null | grep -q 'PUBLIC KEY' || curl -sL https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_10/Release.key | sudo apt-key add -
            apt-get update
            apt-get -y -t buster-backports install libseccomp2
            apt-get -y install podman
            systemctl restart dbus
        fi

        [ -f /etc/bash_completion ] || apt-get install -y bash-completion
        mkdir -p /etc/bash_completion.d
        [ -f /etc/bash_completion.d/podman ] || curl -sL https://raw.githubusercontent.com/containers/podman/master/completions/bash/podman >/etc/bash_completion.d/podman
        grep -q 'alias docker=' /etc/bash.bashrc || echo 'alias docker=\"sudo podman\"' >> /etc/bash.bashrc
        grep -q 'complete -F __start_podman docker' /etc/bash.bashrc || echo 'complete -F __start_podman docker' >> /etc/bash.bashrc
    " unless init
        
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

            if master

              config.vm.provision "PodmanInstall", :type => "shell", :name => "Installing podman", :inline => "
                  if ! which podman >/dev/null 2>&1; then
                      [ $(sysctl -b kernel.unprivileged_userns_clone) = '1' ] || (echo 'kernel.unprivileged_userns_clone=1' >/etc/sysctl.d/00-local-userns.conf && systemctl restart procps)
                      grep -q 'buster-backports main' /etc/apt/sources.list || echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list
                      [ -f /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list ] || echo 'deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_10/ /' >/etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
                      apt-key export devel:kubic 2>/dev/null | grep -q 'PUBLIC KEY' || curl -sL https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_10/Release.key | sudo apt-key add -
                      apt-get update
                      apt-get -y -t buster-backports install libseccomp2
                      apt-get -y install podman
                      systemctl restart dbus
                  fi
          
                  [ -f /etc/bash_completion.d/podman ] || curl -sL https://raw.githubusercontent.com/containers/podman/master/completions/bash/podman >/etc/bash_completion.d/podman
                  grep -q 'alias docker=' /etc/bash.bashrc || echo 'alias docker=\"sudo podman\"' >> /etc/bash.bashrc
                  grep -q 'complete -F __start_podman docker' /etc/bash.bashrc || echo 'complete -F __start_podman docker' >> /etc/bash.bashrc
              "

              config.vm.provision "NFSServer", :type => "shell", :name => 'Installing an NFS server', :inline => "
                export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
                export DEBIAN_FRONTEND=noninteractive
                dpkg -l | grep nfs-kernel-server | grep -q ^ii || apt-get install -y nfs-kernel-server
                mkdir -p /srv/nfs
                chown nobody:nogroup /srv/nfs
                chmod 0777 /srv/nfs
                grep '/srv/nfs' /etc/exports | grep -q #{root_ip} || ( echo \"/srv/nfs #{root_ip}/24(rw,sync,no_subtree_check,no_root_squash)\" >>/etc/exports && systemctl restart nfs-kernel-server )
              "
            end

            if µk8s_version

                if master
                  config.vm.provision "MicroK8sMainConfig", :type => "shell", :name => 'Configuring MicroK8s on main node', :inline => "
                    [ -f /etc/bash_completion ] || apt-get install -y bash-completion
                    [ -f /etc/bash_completion.d/kubectl ] || mkdir -p /etc/bash_completion.d && microk8s kubectl completion bash >/etc/bash_completion.d/kubectl
                    snap alias microk8s.kubectl kubectl
                    snap alias microk8s.kubectl k
                    grep -q 'complete -F __start_kubectl k' /etc/bash.bashrc || echo 'complete -F __start_kubectl k' >> /etc/bash.bashrc
                    microk8s status --wait-ready
                  "
                  config.vm.provision "MicroK8sPlugins", :type => "shell", :name => 'Installing MicroK8s plugins', :inline => "
                    export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
                    export DEBIAN_FRONTEND=noninteractive
                    microk8s enable dns dashboard helm3 rbac
                    snap alias microk8s.helm3 helm
                  "
                  config.vm.provision "NFSCSI", :type => "shell", :name => 'Installing NFS CSI', :inline => "
                    microk8s helm3 repo add csi-driver-nfs https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/charts
                    microk8s helm3 repo update
                    microk8s helm3 install csi-driver-nfs csi-driver-nfs/csi-driver-nfs --namespace kube-system --set kubeletDir=/var/snap/microk8s/common/var/lib/kubelet
                    while ! microk8s kubectl get pods -n kube-system --selector app.kubernetes.io/name=csi-driver-nfs 2>/dev/null | grep -q csi-nfs; do sleep 1; done
                    microk8s kubectl wait pod --selector app.kubernetes.io/name=csi-driver-nfs --for condition=ready --namespace kube-system
                    echo '---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-csi
  annotations:
    storageclass.kubernetes.io/is-default-class: \"true\"
provisioner: nfs.csi.k8s.io
parameters:
  server: #{root_ip}
  share: /srv/nfs
reclaimPolicy: Delete
volumeBindingMode: Immediate
mountOptions:
  - hard
  - nfsvers=4.1' | microk8s kubectl apply -f -
                  "

                else
                    # Joining K8s
                    config.vm.provision "K8SJoin", type: "shell", name: 'Joining the MicroK8s cluster', inline: "
                      ssh -o StrictHostKeyChecking=no #{root_hostname} $(which microk8s) kubectl get no #{hostname} 2>/dev/null | grep -q #{hostname} || (
                        JOIN_CMD=\"$(ssh -o StrictHostKeyChecking=no #{root_hostname} $(which microk8s) add-node --format short | grep '#{root_ip}') --worker\"
                        echo \"#{hostname} joining the cluster\" && 
                        eval $JOIN_CMD
                      )
                    "
                end
            end # k8s

            if µk8s_version && traefik_version
                if master
                    config.vm.provision "TraefikIngress", :type => "shell", :name => "Setting-up Traefik as an Ingress controller", :inline => <<-EOF
                        microk8s helm3 repo list | grep -q traefik || ( microk8s helm3 repo add traefik https://helm.traefik.io/traefik && microk8s helm3 repo update )
                        microk8skubectl get namespaces traefik > /dev/null 2>&1 || microk8s kubectl create namespace traefik
                        microk8s kubectl get ingressclasses.networking.k8s.io > /dev/null 2>&1 && ( microk8s kubectl get ingressclasses.networking.k8s.io traefik-lb >/dev/null 2>&1 || echo '
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata: 
  name: traefik
  annotations:
    ingressclass.kubernetes.io/is-default-class: "true"
spec:
  controller: traefik.io/ingress-controller' | microk8s kubectl apply -f - )
                        microk8s helm3 -n traefik status traefik 2>/dev/null | grep -q deployed || echo '
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
  #{if k8s_db_port && k8s_db_port > 0 then "dashboard:
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
- key: node.kubernetes.io/microk8s-controlplane
  operator: Equal
  effect: NoExecute
- key: node.kubernetes.io/microk8s-controlplane
  operator: Equal
  effect: NoSchedule
nodeSelector:
  node.kubernetes.io/microk8s-controlplane: "microk8s-controlplane"

ingressRoute:
  dashboard:
    enabled: true' | microk8s helm3 install -n traefik traefik traefik/traefik -f -
EOF
                    config.vm.provision "TraefikDashboard", :type => "shell", :name => "Exposing Traefik Dashboard on http://#{root_ip}:#{traefik_db_port}/", :inline => <<-EOF
                        microk8s kubectl -n traefik get ingressroute dashboard >/dev/null 2>&1 || echo '---
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
      kind: TraefikService' | microk8s kubectl apply -f -
                        microk8s kubectl wait pod --selector app.kubernetes.io/name=traefik --for condition=ready --namespace traefik
EOF

                    config.vm.network "forwarded_port", guest: traefik_db_port, host: traefik_db_port if expose_db_ports
                    
                    if k8s_db_port && k8s_db_port > 0
                        config.vm.provision "KubernetesDashboard", :type => "shell", :name => "Exposing Kubernetes Dashboard on http://#{root_ip}:#{k8s_db_port}/", :inline => <<-EOF
                          microk8s kubectl -n kube-system get ingressroute dashboard >/dev/null 2>&1 || (
                            echo "---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
---
apiVersion: v1
kind: Secret
metadata:
  name: admin-user-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: admin-user
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kube-system" | microk8s kubectl apply -f -
                            TOKEN=$(microk8s kubectl -n kube-system get secret $(microk8s kubectl -n kube-system get sa/admin-user -o jsonpath="{.secrets[0].name}") -o go-template="{{.data.token | base64decode}}")
                            echo "---
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: db-bearer-token
  namespace: kube-system
spec:
  headers:
    customRequestHeaders:
      Authorization: \\"Bearer $TOKEN\\"
---
apiVersion: traefik.containo.us/v1alpha1
kind: ServersTransport
metadata:
  name: dashboard-transport
  namespace: kube-system

spec:
  insecureSkipVerify: true
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: dashboard
  namespace: kube-system
spec:
  entryPoints:
    - dashboard
  routes:
    - match: HostRegexp(\\`{host:.+}\\`)
      kind: Rule
      middlewares:
        - name: db-bearer-token
          namespace: kube-system
      services:
        - name: kubernetes-dashboard
          namespace: kube-system
          kind: Service
          port: 443
          scheme: https
          serversTransport: dashboard-transport
" | microk8s kubectl apply -f -
                          )
EOF

                        config.vm.network "forwarded_port", guest: k8s_db_port, host: k8s_db_port if expose_db_ports
                    end # K8S Dashboard over traefik
                end
            end # Traefik

            if master and read_bool_env 'BACKUP'
              config.vm.provision "ImageBackup", :type => "shell", :name => "Exporting necessary images", :inline => "
                  microk8s ctr images ls -q | grep -v sha256 > images.txt
                  microk8s ctr images export images.tar $(cat images.txt)
              "
          end # backup
            
        end # node cfg
    end if init # node
end # config
