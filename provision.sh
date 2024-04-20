#!/usr/bin/env bash

# Halt on errors and undeclared variables.
set -ue

# Generate a random string of 64 bytes.
# shellcheck disable=SC2120
random() {
	openssl rand -hex 32
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
		    Initial server configuration for hosting web applications.
		    See more on https://github.com/corenzan/provision.

		OPTIONS
		    -h --help                       Print out this manual.
		    -l --log <file>                 Log output to file. Defaults to provision-<timestamp>.log. Use '-' to disable.
		    -x --debug                      Print out every command.
		    -n --hostname <hostname>        Server's hostname. Required.
		    -u --username <username>        Administrator's username. Required.
		    -k --public-key <public-key>    File path or URL to administrator's public key. Required.
		    -t --tools-only                 Install just the administrative tools and exit.
		       --dokku                      Install Dokku.
		       --digital-ocean              Install Digital Ocean's monitoring agent.
	EOF
}

# Validate an option was set, bail otherwise.
required() {
	test -n "${!1-}" || bail "Option --$(echo "$1" | tr "_" "-") is required. See --help for more information."
}

# -
# -
# -

# Print help if no arguments were passed.
test $# -gt 0 || { manual; exit 1; }

# Parse options.
options="$(getopt -n "$0" -o hlxn:u:k:t -l help,log,debug,hostname,username,public-key,tools-only,dokku,digital-ocean -- "$@")"

# Bail if parsing failed.
if test $? -ne 0; then
	exit 1
fi

# Restore arguments.
eval set -- "$options"

# Configure script.
if test -n "$options"; then
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
			-n|--hostname)
				hostname="$2"
				shift
				shift
				;;
			-u|--username)
				username="$2"
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
			-t|--tools-only)
				tools_only="tools_only"
				shift
				;;
			--dokku)
				dokku="dokku"
				shift
				;;
			--digital-ocean)
				digital_ocean="digital_ocean"
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
test -n "${debug=}" && set -x

# Set defaults.
log="${log:-provision-$(date +"%Y%m%d%H%M%S").log}"
debug="${debug:-0}"
distro_id="$(lsb_release -is | tr '[:upper:]' '[:lower:]')"
distro_name="$(lsb_release -cs)"

# Let debconf know we won't interact.
export DEBIAN_FRONTEND="noninteractive"

# Log everything if a file was set.
if test "$log" != "-"; then
	exec &> >(tee "$log")
fi

# -
# -
# -

# Install and configure administrative tools and exit.
if test -n "${tools_only=}"; then
	# Validate we're not root.
	test "$(id -u)" -ne 0 || bail "Tools should not be installed as root."

	# Setup tmux.
	git clone --depth=1 https://github.com/gpakosz/.tmux.git "$HOME/.tmux"
	backup "$HOME/.tmux.conf"
	ln -s -f "$HOME/.tmux/.tmux.conf" "$HOME/.tmux.conf"
	cp "$HOME/.tmux/.tmux.conf.local" "$HOME/.tmux.conf.local"

	# Setup vim.
	git clone --depth=1 https://github.com/amix/vimrc.git "$HOME/.vim_runtime"
	sh "$HOME/.vim_runtime/install_basic_vimrc.sh"

	# Setup prezto.
	git clone --recursive https://github.com/sorin-ionescu/prezto.git "$HOME/.zprezto"
	find "$HOME/.zprezto/runcoms" -type f -not -name README.md | while read -r rcfile; do
		rcfile_name=".$(basename "$rcfile")"
		backup "$HOME/$rcfile_name"
		ln -s "$rcfile" "$HOME/$rcfile_name"
	done
	sudo chsh -s "$(which zsh)" "$(id -nu)"

	# Customize shell.
	sed -i "s/  'prompt'/  'syntax-highlighting' 'history-substring-search'/" "$HOME/.zpreztorc"
	sed -i "s/\(zstyle ':prezto:module:prompt' theme\)/#\1/" "$HOME/.zpreztorc"
	cat >> "$HOME/.zshrc" <<-EOF
		# starship prompt
		# https://starship.rs/
		eval "\$(starship init zsh)"

		# Aliases.
		alias g=git
		alias d=docker
		alias c="docker compose"
	EOF

	# Setup starship prompt.
	curl -sS https://starship.rs/install.sh | sh -s -- --yes
	mkdir -p "$HOME/.config"
	starship preset plain-text-symbols > "$HOME/.config/starship.toml"

	# Done.
	exit 0
fi

# -
# -
# -

# Validate --username was set.
required username
required public_key

# Check Linux compatibility.
test "$distro_id" = "ubuntu" || test "$distro_id" = "debian" || bail "Distro '$distro_id' isn't supported."

# Check for required software.
dependencies="apt-get apt-key curl iptables sysctl service hostnamectl locale-gen chpasswd useradd groupadd usermod chown chmod times"
for dep in $dependencies; do
	if ! type "$dep" >/dev/null 2>&1; then
		bail "$dep could not be found, which is a hard dependency along with: $dependencies."
	fi
done

# Require privilege, i.e. sudo, after administrative tools block.
test "$(id -u)" -eq 0 || bail "This script must be run as root."

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

# Clear rules for IPv4.
iptables -F
iptables -t nat -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Clear rules for IPv6.
ip6tables -F
ip6tables -t nat -F
ip6tables -P INPUT ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -P FORWARD ACCEPT

# Accept anything from/to loopback interface in IPv4.
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Accept anything from/to loopback interface in IPv6.
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

# Keep established or related connections in IPv4.
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Keep established or related connections in IPv6.
ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow DNS communication in IPv4.
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Allow DNS communication in IPv6.
ip6tables -A INPUT -p tcp --dport 53 -j ACCEPT
ip6tables -A INPUT -p udp --dport 53 -j ACCEPT

# Allow regular pings in IPv4.
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Allow regular pings in IPv6.
ip6tables -A INPUT -p icmpv6 -j ACCEPT

# Allow dockerd communication in IPv4.
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 2375 -j ACCEPT

# Allow dockerd communication in IPv6.
ip6tables -A INPUT -s ::1 -p tcp --dport 2375 -j ACCEPT

# Allow incoming traffic for HTTP, HTTPS and SSH in IPv4.
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 822 -j ACCEPT

# Allow incoming traffic for HTTP, HTTPS and SSH in IPv6.
ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 822 -j ACCEPT

# Block any other incoming connections in IPv4.
iptables -A INPUT -j DROP

# Block any other incoming connections in IPv6.
ip6tables -A INPUT -j DROP

# Log all the traffic in IPv4.
iptables -A INPUT -j LOG --log-tcp-options --log-prefix "[iptables] "
iptables -A FORWARD -j LOG --log-tcp-options --log-prefix "[iptables] "

# Log all the traffic in IPv6.
ip6tables -A INPUT -j LOG --log-tcp-options --log-prefix "[ip6tables] "
ip6tables -A FORWARD -j LOG --log-tcp-options --log-prefix "[ip6tables] "

# Pipe iptables log to its own file.
cat > /etc/rsyslog.d/10-iptables.conf <<-EOF
	:msg, contains, "[iptables] " -/var/log/iptables.log
	& stop
EOF

# Pipe ip6tables log to its own file.
cat > /etc/rsyslog.d/10-ip6tables.conf <<-EOF
	:msg, contains, "[ip6tables] " -/var/log/ip6tables.log
	& stop
EOF

# Apply rsyslog configuration.
service rsyslog restart

# Rotate iptables logs.
cat > /etc/logrotate.d/iptables <<-EOF
	/var/log/iptables.log
	{
		rotate 30
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

# Rotate ip6tables logs.
cat > /etc/logrotate.d/ip6tables <<-EOF
	/var/log/ip6tables.log
	{
		rotate 30
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

# Setup Digital Ocean monitoring agent.
if test -n "${digital_ocean=}"; then
	curl -sSL https://insights.nyc3.cdn.digitaloceanspaces.com/install.sh | bash || echo "Failed to install DO monitoring agent. Continuing..."
fi

# Setup Dokku.
if test -n "${dokku=}"; then
	DOKKU_TAG=v0.34.4
	curl -fsSL "https://raw.githubusercontent.com/dokku/dokku/$DOKKU_TAG/bootstrap.sh" | bash
	dokku domains:set-global "$hostname"
fi

# Save iptables configuration, but only after installing new packages, since they might have modified the rules.
iptables-save > /etc/iptables.conf

# Save ip6tables configuration, but only after installing new packages, since they might have modified the rules.
ip6tables-save > /etc/ip6tables.conf

# Load iptables config when network device is up.
cat > /etc/network/if-up.d/iptables <<-EOF
	#!/usr/bin/env bash
	iptables-restore < /etc/iptables.conf
EOF
chmod +x /etc/network/if-up.d/iptables

# Load ip6tables config when network device is up.
cat > /etc/network/if-up.d/ip6tables <<-EOF
	#!/usr/bin/env bash
	ip6tables-restore < /etc/ip6tables.conf
EOF
chmod +x /etc/network/if-up.d/ip6tables

# Write custom Docker configuration.
# https://docs.docker.com/engine/reference/commandline/dockerd/
cat > /etc/docker/daemon.json <<-EOF
	{
	  "live-restore": true,
	  "log-driver": "json-file",
	  "log-opts": {
	    "max-size": "8m",
	    "max-file": "16"
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
if test -n "${dokku=}"; then
	usermod -aG remote dokku
fi

# Create a new administrator user.
password="$(random)"
useradd -d "/home/$username" -m -s /bin/bash "$username"
chpasswd <<< "$username:$password"
usermod -aG sudo,remote,docker "$username"
echo "-> $username:$password"

# Do not ask for password when sudoing.
backup /etc/sudoers
sed -i '/^%sudo/c\%sudo\tALL=(ALL:ALL) NOPASSWD:ALL' /etc/sudoers

# Setup RSA key for secure SSH authorization.
mkdir -p "/home/$username/.ssh"
echo "$public_key" >> "/home/$username/.ssh/authorized_keys"
chown -R "$username:$username" "/home/$username/.ssh"

# Authorize deploys to dokku.
if test -n "${dokku=}"; then
	dokku ssh-keys:add "$username" "/home/$username/.ssh/authorized_keys"
fi

# Save a copy.
backup /etc/ssh/sshd_config

# Configure the SSH server.
cat > /etc/ssh/sshd_config <<-EOF
	# We omit ListenAddress so SSHD listens on all interfaces, both IPv4 and IPv6.

	# Supported HostKey algorithms by order of preference.
	HostKey /etc/ssh/ssh_host_ed25519_key
	HostKey /etc/ssh/ssh_host_rsa_key
	HostKey /etc/ssh/ssh_host_ecdsa_key

	# Choose stronger Key Exchange algorithms.
	KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

	# Use modern ciphers for encryption.
	Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

	# Use MACs with larger tag sizes.
	MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

	# LogLevel VERBOSE logs user's key fingerprint on login. Needed to have a clear audit track of which key was using to log in.
	LogLevel VERBOSE

	# Don't let users set environment variables.
	PermitUserEnvironment no

	# Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.
	Subsystem sftp internal-sftp -f AUTHPRIV -l INFO

	# Only use the newer more secure protocol.
	Protocol 2

	# Forwarding to X11 is considered insecure.
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
awk '$5 >= 3071' /etc/ssh/moduli.default > /etc/ssh/moduli

# Delete existing host keys.
rm /etc/ssh/ssh_host_*

# Create new host keys.
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""

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

# Setup administrative tools as the administrator.
su - "$username" -c "bash -s -- --tools-only $options" < "$0"

# Output execution time.
times
