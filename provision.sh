#!/usr/bin/env bash

if [ $(id -u) != 0 ]; then
    echo Try sudo $0. >&2
    exit 1
fi

if ! type apt-get >/dev/null 2>&1; then
    echo This script depends on aptitude. >&2
    exit 1
fi

cat <<EOF
  ____                 _     _             
 |  _ \ _ __ _____   _(_)___(_) ___  _ __  
 | |_) | '__/ _ \ \ / / / __| |/ _ \| '_ \ 
 |  __/| | | (_) \ V /| \__ \ | (_) | | | |
 |_|   |_|  \___/ \_/ |_|___/_|\___/|_| |_|

Please note that this script will:

    - Reset root's password.
    - Upgrade all installed packages.
    - Install third-party software.
    - Block all external communication except on ports 822, 80, and 443.
    - Setup swap space with half the available memory.
    - Output secrets in plain text.

Also, you should have at hand:

    - Your RSA public key.
    - Your New Relic license key.

EOF
read -rsp "Press ENTER to continue or CTRL-C to abort..." any

# Halt on error and undeclared variables.
set -uex

# Make it non interactive.
DEBIAN_FRONTEND=noninteractive

# Generate a secret.
secret() {
    local LC_CTYPE=C
    cat /dev/urandom | tr -dc A-Za-z0-9 | head -c ${1:-64}
}

# Log everything.
log_file=provision-$(date +%s).log
exec > >(tee $log_file) 2>&1

# Add New Relic repository to the source list.
echo "deb http://apt.newrelic.com/debian/ newrelic non-free" >> /etc/apt/sources.list.d/newrelic.list
curl -fsSL https://download.newrelic.com/548C16BF.gpg | apt-key add -

# Add Docker repository to the source list.
echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable" >> /etc/apt/sources.list.d/docker.list
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -

# Refresh repositories and upgrade packages.
apt-get update
apt-get upgrade -y
apt-get autoremove

# Setup encoding.
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
update-locale LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8
locale-gen en_US.UTF-8

# Disable IPV6.
cat >> /etc/sysctl.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p
cat /proc/sys/net/ipv6/conf/all/disable_ipv6

# Clear firewall rules.
iptables -F
iptables -t nat -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Accept anything from/to loopback interface.
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Docker client/server communication.
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 2375 -j ACCEPT

# Keep established or related connections.
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow TCP connections using ports for HTTP, HTTPS and SSH.
acceptable_ports="822 80 443"
for port in $acceptable_ports; do
  iptables -A INPUT -p tcp --dport $port -j ACCEPT;
done

# Allow regular pings.
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Block any other input.
iptables -A INPUT -j DROP

# Load firewall settings when network device is up.
cat > /etc/network/if-up.d/iptables <<EOF
#!/usr/bin/env bash
iptables-restore < /etc/iptables.conf
EOF
chmod +x /etc/network/if-up.d/iptables

# Change root's password.
password=$(secret)
chpasswd <<< "root:$password"
cat <<EOF
root
$password
EOF

# Create an administrator account.
username="arthur"
password=$(secret)
useradd -d /home/$username -m -s /bin/bash $username
chpasswd <<< "$username:$password"
usermod -aG sudo $username
cat <<EOF
$username
$password
EOF

# Do not ask for password when sudoing.
sed -i '/^%sudo/c\%sudo\tALL=(ALL:ALL) NOPASSWD:ALL' /etc/sudoers

# Setup RSA key for secure SSH authorization.
read -e -p "$username's public key: " public_key
mkdir -p /home/$username/.ssh
echo "$public_key" >> /home/$username/.ssh/authorized_keys
chown -R $username:$username /home/$username/.ssh

# Set some secure defaults for SSH.
cat > /etc/ssh/sshd_config <<EOF
Port 822
LoginGraceTime 20
PermitRootLogin no
PasswordAuthentication no
AllowUsers $username
DebianBanner no
MaxAuthTries 2
MaxSessions 2
EOF
service ssh restart

# Setup common software.
apt-get install -y build-essential git fail2ban newrelic-sysmond unattended-upgrades
read -e -p "New Relic license key: " new_relic_key
nrsysmond-config --set license_key=$new_relic_key
/etc/init.d/newrelic-sysmond start

# Save firewall configuration after installing fail2ban.
iptables-save > /etc/iptables.conf

# Setup unattended security upgrades.
cat > /etc/apt/apt.conf.d/10periodic <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Setup swap space.
total_memory=$(free -m | awk '/^Mem:/{print $2}')
fallocate -l $[total_memory/2]KB /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
echo 'vm.swappiness = 10' >> /etc/sysctl.conf
sysctl -p
