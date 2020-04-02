Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"
  
  config.vm.provider "virtualbox" do |provider|
    provider.memory = "1024"
  end
  
  config.vm.network "private_network", ip: "10.133.7.123"
  config.vm.hostname = "provision"

  config.vm.synced_folder ".", "/provision"
  
  config.vm.provision "shell", inline: "/provision/provision.sh -x -u arthur -k https://gist.githubusercontent.com/haggen/e9f9ef40da12f209ee630be5d7ba3805/raw/06adcfb30c6b434adafbc698b78d9d1a083144c2/id_rsa.pub"

  # config.vm.define "node-1" do |node1_config|
  #   node1_config.vm.network "private_network", ip: "10.133.7.123"
  #   node1_config.vm.hostname = "node-1"
  # end
  
  # config.vm.define "node-2" do |node2_config|
  #   node2_config.vm.network "private_network", ip: "10.133.7.124"
  #   node2_config.vm.hostname = "node-2"
  # end
end
