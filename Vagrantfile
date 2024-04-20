Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"

  config.vm.provider "virtualbox" do |provider|
    provider.memory = "1024"
    # Fixing issue with serial port.
    provider.customize ["modifyvm", :id, "--uartmode1", "disconnected"]
  end

  config.vm.network "private_network", ip: "192.168.56.7"
  config.vm.hostname = "provision"

  config.vm.provision "file", source: "./provision.sh", destination: "/tmp/provision.sh"
  config.vm.provision "shell", inline: "/tmp/provision.sh -x -u arthur -n example.com -k https://gist.githubusercontent.com/haggen/e9f9ef40da12f209ee630be5d7ba3805/raw/06adcfb30c6b434adafbc698b78d9d1a083144c2/id_rsa.pub"
end
