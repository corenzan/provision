#!/usr/bin/env bash

# Halt on errors and undeclared variables.
set -ue

# Generate a random string of length $1 (64).
random() {
	local LC_CTYPE=C
	tr -dc A-Za-z0-9 < /dev/urandom | head -c ${1:-64}
}

# Make a backup copy.
backup() {
	if test -f $1; then
		cp $1 $1.backup-$(date +"%Y%m%d%H%M%S")
	fi
}

# Complain and quit.
die() {
	echo "$0: $1" >&2
	exit 1
}

# Print out the manual.
manual() {
	cat <<-EOF >&2
		SYNOPSIS
		    Feed your servers. See https://github.com/corenzan/provision

		OPTIONS
		    -h,--help          Display this.
		    -l,--log           Save output to file.
		    -x,--debug         Print out every command.
		    -u,--username      Administrator's username.
		    -k,--public-key    Path or URL to administrator's public key.
	EOF
}

# -
# -
# -

# Parse options.
flags=$(getopt -n "$0" -o hlxu:k: -l help,log,debug,username,public-key -- "$@")

# Bail if parsing failed.
if test $? -ne 0; then
	exit 1
fi

# Restore arguments.
eval set -- "$flags"

# Configure script.
if test -n "$flags"; then
	while :; do
		case "$1" in
			-h|--help)
				manual
				exit
				;;
			-l|--log)
				log="$2"
				shift
				shift
				;;
			-x|--debug)
				debug=1
				shift
				;;
			-u|--username)
				administrator="$2"
				shift
				shift
				;;
			-k|--public-key)
				if test "${2#http}" != "$2"; then
					public_key="$(curl -fsL $2)"
				elif test -f "$2"; then
					public_key="$(cat $2)"
				else
					die "Public key could not be read from '$2'."
				fi
				shift
				shift
				;;
			--)
				shift
				break
				;;
		esac
	done
fi

# Set defaults.
log=${log:-provision-$(date +"%Y%m%d%H%M%S").log}
debug=${debug:-0}
linux_id="$(lsb_release -is | tr '[A-Z]' '[a-z]')"
linux_codename="$(lsb_release -cs)"

# -
# -
# -

# Enable debug.
test $debug -ne 0 && set -x

# Whine about missing options.
test -n "$administrator" || die "Flag --username is required. Try --help."
test -n "$public_key" || die "Flag --public-key is required. Try --help."

# Check Linux compatibility.
test "$linux_id" = "ubuntu" || test "$linux_id" = "debian" || die "Distro '$linux_id' hasn't been tested."

# Require privilege, i.e. sudo.
test $(id -u) -eq 0 || { sudo $0 $flags; exit 0; }

# Log everything.
test "$log" = "-" || exec > >(time tee $log) 2>&1

# Test for the presence of expected software.
dependency="apt-get apt-key curl iptables sysctl service"
for dep in $dependency; do
	if ! type $dep >/dev/null 2>&1; then
		die "$dep could not be found, which is a hard dependency along with: $dependency."
	fi
done

# Let debconf know we won't interact.
export DEBIAN_FRONTEND=noninteractive

# Add Docker repository to the source list.
curl -fsSL https://download.docker.com/linux/$linux_id/gpg | apt-key add -
echo "deb [arch=amd64] https://download.docker.com/linux/$linux_id $linux_codename stable" >> /etc/apt/sources.list.d/docker.list

# Refresh repositories and upgrade installed packages.
apt-get update
apt-get upgrade -y
apt-get autoremove -y

# Configure environment encoding.
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
update-locale LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8
locale-gen en_US.UTF-8

# Disable IPv6 for now, pending:
# - Compatibility with Docker/Docker Swarm.
# - Firewall with ip6tables.
cat >> /etc/sysctl.conf <<-EOF
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

# Keep established or related connections.
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow DNS communication.
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Allow regular pings.
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Docker communication.
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 2375 -j ACCEPT

# Allow incoming traffic for HTTP, HTTPS and SSH.
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 822 -j ACCEPT

# Block any other incoming connections.
iptables -A INPUT -j DROP

# Log all the traffic.
iptables -A INPUT -j LOG --log-tcp-options --log-prefix "[iptables] "
iptables -A FORWARD -j LOG --log-tcp-options --log-prefix "[iptables] "

# Pipe iptables log to its own file.
cat > /etc/rsyslog.d/10-iptables.conf <<-EOF
	:msg, contains, "[iptables] " -/var/log/iptables.log
	& stop
EOF
service rsyslog restart

# Rotate iptables log so it doesn't fill up the disk.
cat > /etc/logrotate.d/iptables <<-EOF
	/var/log/iptables.log
	{
		rotate 7
		daily
		missingok
		notifempty
		delaycompress
		compress
		postrotate
			invoke-rc.d rsyslog rotate > /dev/null
		endscript
	}
EOF

# Setup common software.
apt-get install -y build-essential apt-transport-https ca-certificates software-properties-common ntp git gnupg2 fail2ban unattended-upgrades docker-ce

# Setup DO monitoring agent.
curl -sSL https://insights.nyc3.cdn.digitaloceanspaces.com/install.sh | bash

# Setup Dokku.
DOKKU_TAG=v0.20.0
curl -fsSL https://raw.githubusercontent.com/dokku/dokku/$DOKKU_TAG/bootstrap.sh | bash

# Only dump iptables configuration after installing all the software.
iptables-save > /etc/iptables.conf

# Load iptables config when network device is up.
cat > /etc/network/if-up.d/iptables <<-EOF
	#!/usr/bin/env bash
	iptables-restore < /etc/iptables.conf
EOF
chmod +x /etc/network/if-up.d/iptables

# Write custom Docker configuration.
# https://docs.docker.com/engine/reference/commandline/dockerd/
cat > /etc/docker/daemon.json <<-EOF
	{
		"live-restore": true,
		"storage-driver": "overlay2",
		"log-driver": "json-file",
		"log-opts": {
			"max-size": "8m",
			"max-file": "8"
		}
	}
EOF

# Clean downloaded packages.
apt-get clean

# Reset root password.
password="$(random)"
chpasswd <<< "root:$password"
echo "-> root:$password"

# Create a new SSH group.
groupadd remote

# Add dokku user to remote group.
usermod -aG remote dokku

# Create a new administrator user.
password="$(random)"
useradd -d /home/$administrator -m -s /bin/bash $administrator
chpasswd <<< "$administrator:$password"
usermod -aG sudo,remote,docker $administrator
echo "-> $administrator:$password"

# Do not ask for password when sudoing.
backup /etc/sudoers
sed -i '/^%sudo/c\%sudo\tALL=(ALL:ALL) NOPASSWD:ALL' /etc/sudoers

# Setup RSA key for secure SSH authorization.
mkdir -p /home/$administrator/.ssh
echo "$public_key" >> /home/$administrator/.ssh/authorized_keys
chown -R $administrator:$administrator /home/$administrator/.ssh

# Save a copy.
backup /etc/ssh/sshd_config

# Configure the SSH server.
cat > /etc/ssh/sshd_config <<-EOF
	# Supported HostKey algorithms by order of preference.
	HostKey /etc/ssh/ssh_host_ed25519_key
	HostKey /etc/ssh/ssh_host_rsa_key
	HostKey /etc/ssh/ssh_host_ecdsa_key

	KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
	Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

	# LogLevel VERBOSE logs user's key fingerprint on login. Needed to have a clear audit track of which key was using to log in.
	LogLevel VERBOSE

	# Don't let users set environment variables.
	PermitUserEnvironment no

	# Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.
	Subsystem sftp internal-sftp -f AUTHPRIV -l INFO

	# Only use the newer more secure protocol.
	Protocol 2

	# Dorwarding as X11 is very insecure.
	# You really shouldn't be running X on a server anyway.
	X11Forwarding no

	# Disable port forwarding.
	AllowTcpForwarding no
	AllowStreamLocalForwarding no
	GatewayPorts no
	PermitTunnel no

	# Don't allow login if the account has an empty password.
	PermitEmptyPasswords no

	# Ignore .rhosts and .shosts.
	IgnoreRhosts yes

	# Verify hostname matches IP.
	UseDNS no

	# TCPKeepAlive is not encrypted.
	TCPKeepAlive no

	AllowAgentForwarding no
	Compression no

	# Forbid root sessions.
	PermitRootLogin no

	# Don't allow .rhosts or /etc/hosts.equiv.
	HostbasedAuthentication no

	# Allow users in 'remote' group to connect.
	# To add and remove users from the group, respectively:
	# - usermod -aG remote <username>
	# - gpasswd -d <username> remote 
	AllowGroups remote
	
	# Drop clients that idle longer than 10 minutes.
	ClientAliveInterval 60
	ClientAliveCountMax 10
	
	# Listen everywhere.
	ListenAddress 0.0.0.0

	# Drop if a client take too long to authenticate.
	LoginGraceTime 10

	# Log additional failures.
	MaxAuthTries 2

	# Limit connections from the same network.
	MaxSessions 10

	# Allow only one authentication at a time.
	MaxStartups 1

	# Password are insecure.
	PasswordAuthentication no

	# Silence is golden.
	DebianBanner no

	# Change default port.
	Port 822
EOF

# The Diffie-Hellman algorithm is used by SSH to establish a secure connection.
# The larger the moduli (key size) the stronger the encryption.
# Remove all moduli smaller than 3072 bits.
cp --preserve /etc/ssh/moduli /etc/ssh/moduli.default
awk '$5 >= 3071' /etc/ssh/moduli | tee /etc/ssh/moduli.tmp
mv /etc/ssh/moduli.tmp /etc/ssh/moduli

# Restart SSH server.
service ssh restart

# Create swap space equivalent to the available memory.
memory=$(free -m | awk '/^Mem:/{print $2}')
fallocate -l ${memory}MB /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
backup /etc/fstab
echo '/swapfile none swap sw 0 0' >> /etc/fstab
backup /etc/sysctl.conf
echo 'vm.swappiness = 10' >> /etc/sysctl.conf
sysctl -p

