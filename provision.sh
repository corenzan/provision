#!/usr/bin/env bash

# Generate a random string
random() {
	local LC_CTYPE=C
	cat /dev/urandom | tr -dc A-Za-z0-9 | head -c ${1:-64}
}

# Log everything
log_file=provision-$(date +%s).log
exec > >(tee $log_file) 2>&1

# Require privilege (a.k.a. sudo)
if test $(id -u) -ne 0; then
	echo "🚫 Try again with root or sudo." >&2
	exit 1
fi

# Test for the presence of required software
dependency=(apt apt-key curl iptables)
for dep in $dependency; do
	if ! type $dep >/dev/null 2>&1; then
		echo "🚫 '$dep' could not be found, which is a hard dependency along with: $dependency." >&2
		exit 1
	fi
done

printf "
  ____                 _     _
 |  _ \\ _ __ _____   _(_)___(_) ___  _ __
 | |_) | '__/ _ \\ \\ / / / __| |/ _ \\| '_ \\
 |  __/| | | (_) \\ V /| \\__ \\ | (_) | | | |
 |_|   |_|  \\___/ \\_/ |_|___/_|\\___/|_| |_|

⚠ Please note that this script will:

	- Reset root's password.
	- Create a new administrator user and setup SSH in an alternative port (822).
	- Upgrade all installed packages and install third-party software.
	- Block all incoming traffic except on ports 822 (for SSH), 80, and 443.
	- Setup swap space with half the available memory.
	- It'll \e[7moutput secrets in plain text\e[0m.

🗒 You should have at hand:

	- Your RSA public key.

🕵 Also you can re-execute this script with --debug to have each step printed on screen.

"

# Confirm before continueing
read -rsp "🚦 Press ENTER to continue or CTRL-C to abort..." _

# Enable debug with --debug
test "$1" = "--debug" && set -x

# Halt on error or undeclared variables
set -ueo pipefail

# Flag it as non interactive
DEBIAN_FRONTEND=noninteractive

# Add Docker repository to the source list
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" >> /etc/apt/sources.list.d/docker.list

# Add Kubernetes repository to the source list
# TODO: As of this edit kubernetes doesn't officially support Ubuntu 18.04
# "bionic" but the channel for the previous release "xenial" works just fine.
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
#echo "deb http://apt.kubernetes.io/ kubernetes-$(lsb_release -cs) main" > /etc/apt/sources.list.d/kubernetes.list
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list

# Refresh repositories and upgrade packages
apt update
apt upgrade -y
apt autoremove -y

# Setup environment encoding
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
update-locale LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8
locale-gen en_US.UTF-8

# Disable IPV6 because we're on Digital Ocean
# - https://github.com/dokku/dokku/blob/4008919a3c8b1cf440d010f448215d0776938f88/docs/getting-started/install/digitalocean.md
# - https://twitter.com/ksaitor/status/1021435996230045697
#cat >> /etc/sysctl.conf <<EOF
#net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.default.disable_ipv6 = 1
#net.ipv6.conf.lo.disable_ipv6 = 1
#EOF
#sysctl -p
#cat /proc/sys/net/ipv6/conf/all/disable_ipv6

# Clear firewall rules
iptables -F
iptables -t nat -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Accept anything from/to loopback interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Docker client/server communication
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 2375 -j ACCEPT

# Keep established or related connections
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow TCP connections using ports for HTTP, HTTPS and SSH
acceptable_ports="822 80 443"
for port in $acceptable_ports; do
	iptables -A INPUT -p tcp --dport $port -j ACCEPT;
done

# Allow regular pings
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Block any other input
iptables -A INPUT -j DROP

# Setup common software
apt install -y build-essential apt-transport-https ca-certificates curl software-properties-common git fail2ban unattended-upgrades docker-ce kubeadm kubelet kubectl

# Only dump iptables configuration after installing fail2ban, Docker, and kubernetes
iptables-save > /etc/iptables.conf

# Clean downloaded packages
apt clean

# Load iptables config when network device is up
cat > /etc/network/if-up.d/iptables <<EOF
#!/usr/bin/env bash
iptables-restore < /etc/iptables.conf
EOF
chmod +x /etc/network/if-up.d/iptables

# Change root password
password=$(random)
chpasswd <<< "root:$password"
echo "🔒 root:$password"

# Create an administrator account
read -p "👉 Administrator username (arthur): " username
username=${username:-arthur}
password=$(random)
useradd -d /home/$username -m -s /bin/bash $username
chpasswd <<< "$username:$password"
usermod -aG sudo $username
usermod -aG docker $username
echo "🔒 $username:$password"

# Do not ask for password when sudoing
sed -i '/^%sudo/c\%sudo\tALL=(ALL:ALL) NOPASSWD:ALL' /etc/sudoers

# Setup RSA key for secure SSH authorization
read -e -p "👉 $username's public key: " public_key
mkdir -p /home/$username/.ssh
echo "$public_key" >> /home/$username/.ssh/authorized_keys
chown -R $username:$username /home/$username/.ssh

# Set some secure defaults for SSH
cat > /etc/ssh/sshd_config <<EOF
Port 822
LoginGraceTime 20
PermitRootLogin no
PasswordAuthentication no
AllowUsers $username dokku
ClientAliveInterval 60
ClientAliveCountMax 10
DebianBanner no
MaxAuthTries 1
MaxSessions 1
EOF
service ssh restart

# Make sure there's no swap (kubernetes doesn't like it)
swapoff -a

# Ask for a hostname
read -p "👉 Hostname: " hostname
hostnamectl set-hostname $hostname
