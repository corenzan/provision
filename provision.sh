#!/usr/bin/env bash

# Halt on errors and undeclared variables.
set -ue

# Generate a random string of length $1 (64).
random() {
	local LC_CTYPE=C
	tr -dc A-Za-z0-9 < /dev/urandom | head -c 64
}

# Make a backup copy of a file.
backup() {
	if test -f "$1"; then
		cp "$1" "$1.backup-$(date +"%Y%m%d%H%M%S")"
	fi
}

# Complain and quit.
bail() {
	echo "$0: $1" >&2
	exit 1
}

# Print out the manual.
manual() {
	cat <<-EOF >&2
		SYNOPSIS
		    Initial server configuration for hosting web applications. See https://github.com/corenzan/provision

		OPTIONS
		    -h --help                       Print out the manual.
		    -l --log <file>                 Save output to file. Defaults to provision*.log.
		    -x --debug                      Print out every command.
		    -n --hostname <hostname>        Server's hostname.
		    -u --username <username>        Administrator's username.
		    -k --public-key <public-key>    File path or URL to administrator's public key.
		    -t --tools                      Just install administrative tools and exit.
	EOF
}

# -
# -
# -

# Parse options.
flags="$(getopt -n "$0" -o hlxu:k:tn: -l help,log,debug,username,public-key,tools,hostname -- "$@")"

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
					public_key="$(curl -fsL "$2")"
				elif test -f "$2"; then
					public_key="$(cat "$2")"
				else
					bail "Public key could not be read from '$2'."
				fi
				shift
				shift
				;;
			-n|--hostname)
				hostname="$2"
				shift
				shift
				;;
			-t|--tools)
				tools="1"
				shift
				;;
			--)
				shift
				break
				;;
		esac
	done
fi

# Enable debug.
test $debug -ne 0 && set -x

# Set defaults.
log="${log:-provision-$(date +"%Y%m%d%H%M%S").log}"
debug="${debug:-0}"
distro_id="$(lsb_release -is | tr '[:upper:]' '[:lower:]')"
distro_name="$(lsb_release -cs)"

# Let debconf know we won't interact.
export DEBIAN_FRONTEND="noninteractive"

# Whine if mandatory options are missing.
test -n "${administrator=}" || bail "Option --username is required. See --help."
test -n "${public_key=}" || bail "Option --public-key is required. See --help."

# Log everything either to stdout/stderr or to a file.
test "$log" = "-" || exec 2>&1 | time tee "$log"

# -
# -
# -

# Install and configure administrative tools and exit.
# - tmux
# - vim
# - prezto
# - starship prompt
if test -n "${tools=}"; then
	git clone https://github.com/gpakosz/.tmux.git "$HOME/.tmux"
	ln -s -f "$HOME/.tmux/.tmux.conf" "$HOME"

	git clone --depth=1 https://github.com/amix/vimrc.git "$HOME/.vim_runtime"
	sh ~/.vim_runtime/install_basic_vimrc.sh

	git clone --recursive https://github.com/sorin-ionescu/prezto.git "$HOME/.zprezto"
	find "$HOME/.zprezto/runcoms" -type f -not -name README.md | while read -r rcfile; do
		ln -s "$rcfile" "$HOME/.$rcfile"
	done
	chsh -s "$(which zsh)" "$(id -nu)"

	curl -fsSL https://starship.rs/install.sh | sh -c

	exit 0
fi

# Check Linux compatibility.
test "$distro_id" = "ubuntu" || test "$distro_id" = "debian" || bail "Distro '$distro_id' isn't supported."

# Add Docker repository to the source list.
curl -fsSL "https://download.docker.com/linux/$distro_id/gpg" | apt-key add -
echo "deb [arch=amd64] https://download.docker.com/linux/$distro_id $distro_name stable" >> /etc/apt/sources.list.d/docker.list

# Refresh repositories and upgrade installed packages.
apt-get update
apt-get upgrade -y
apt-get autoremove -y

# Configure environment encoding.
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
update-locale LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8
locale-gen en_US.UTF-8

# Update hostname.
hostnamectl set-hostname "$hostname"

# Disable IPv6 for now, pending:
# - Compatibility with Docker.
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

# Allow dockerd communication.
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
apt-get install -y build-essential apt-transport-https ca-certificates software-properties-common ntp git gnupg2 fail2ban unattended-upgrades docker-ce tmux zsh vim

# Setup DO monitoring agent.
curl -sSL https://insights.nyc3.cdn.digitaloceanspaces.com/install.sh | bash

# Setup Dokku.
DOKKU_TAG=v0.27.0
curl -fsSL "https://raw.githubusercontent.com/dokku/dokku/$DOKKU_TAG/bootstrap.sh" | bash
dokku domains:set-global "$hostname"

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
useradd -d "/home/$administrator" -m -s /bin/bash "$administrator"
chpasswd <<< "$administrator:$password"
usermod -aG sudo,remote,docker "$administrator"
echo "-> $administrator:$password"

# Do not ask for password when sudoing.
backup /etc/sudoers
sed -i '/^%sudo/c\%sudo\tALL=(ALL:ALL) NOPASSWD:ALL' /etc/sudoers

# Setup RSA key for secure SSH authorization.
mkdir -p "/home/$administrator/.ssh"
echo "$public_key" >> "/home/$administrator/.ssh/authorized_keys"
chown -R "$administrator:$administrator" "/home/$administrator/.ssh"

# Authorize deploys to dokku.
dokku ssh-keys:add "$administrator" "/home/$administrator/.ssh/authorized_keys"

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
fallocate -l "${memory}MB" /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
backup /etc/fstab
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Reduce swappiness (how likely the system is to swap memory).
backup /etc/sysctl.conf
echo 'vm.swappiness = 10' >> /etc/sysctl.conf
sysctl -p

# Setup administrative tools as the administrator user.
sudo -i -u "$administrator" "$0" "$@" --tools