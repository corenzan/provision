#!/usr/bin/env bash


# Require privilege (a.k.a. sudo)
if test $(id -u) -ne 0; then
	echo "🚫 Try again with root or sudo." >&2
	exit 1
fi

if ! type apt-get >/dev/null 2>&1; then
    echo "Aptitude (apt-get) could not be found. This script requires aptitude and has only be tested in Debian or its derived systems." >&2
    exit 1
fi

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

set -ue
# Halt on error or undeclared variables

# Flag it as non interactive
DEBIAN_FRONTEND=noninteractive

# Generate a random string.
random() {
    local LC_CTYPE=C
    cat /dev/urandom | tr -dc A-Za-z0-9 | head -c ${1:-64}
}

# Log everything.
log_file=provision-$(date +%s).log
exec > >(tee $log_file) 2>&1

echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu zesty stable" >> /etc/apt/sources.list.d/docker.list
# Add Docker repository to the source list
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -

apt-get update
apt-get upgrade -y
apt-get autoremove -y
# Refresh repositories and upgrade packages

# Setup environment encoding
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
update-locale LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8
locale-gen en_US.UTF-8

# Disable IPV6.
# https://medium.com/@jonasotten/docker-on-digitalocean-with-a-public-ipv6-address-for-each-container-e908c73dbee6
cat >> /etc/sysctl.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p
cat /proc/sys/net/ipv6/conf/all/disable_ipv6

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

apt-get install -y build-essential apt-transport-https ca-certificates curl software-properties-common git fail2ban unattended-upgrades docker-ce
# Setup common software

DOKKU_TAG=v0.10.5
# Setup Dokku
curl -s https://raw.githubusercontent.com/dokku/dokku/$DOKKU_TAG/bootstrap.sh | bash

# Only dump iptables configuration after installing fail2ban and Docker
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
DebianBanner no
MaxAuthTries 2
MaxSessions 2
EOF
service ssh restart

# Setup unattended security upgrades
cat > /etc/apt/apt.conf.d/10periodic <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Setup swap space with half the memory available
memory=$(free -m | awk '/^Mem:/{print $2}')
fallocate -l $((memory/2))KB /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
echo 'vm.swappiness = 10' >> /etc/sysctl.conf
sysctl -p
