#!/usr/bin/env sh

# Halt on errors and undeclared variables.
set -ue

# Generate a random string of 64 bytes.
random() {
	tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64
}

# Backup a file.
backup() {
	if test -f "$1"; then
		cp -p "$1" "$1.$now"
	fi
}

# Replace file contents, atomically and with backup.
put() {
	temp="$(mktemp)"
	cat >"$temp"
	backup "$1"
	mv "$temp" "$1"
}

# Print out an error message and exit.
fatal() {
	echo "provision: $1" >&2
	exit 1
}

# Print out the manual.
manual() {
	cat <<-EOF >&2
		SYNOPSIS
		    Set up a Debian based linux server.

		USAGE
		    provision.sh [global options] <command> [command options]

		GLOBAL OPTIONS
		    -h               Print out this manual.
		    -l <file>        Log output to file. Defaults to provision-<timestamp>.log. Use '-' to disable.
		    -x               Print each command.

		COMMANDS
		    init             Initialize the server configuration.
		    register         Register a new system administrator user and authorize their key.
		    tools            Install opinionated administrative tools for the current user.

		INIT OPTIONS
		    -n <hostname>    Server's hostname. Required.
		
		REGISTER OPTIONS
		    -u <username>    Administrator's username. Required.
		    -k <public key>  File path or URL to administrator's public key. Required.
		
		TOOLS OPTIONS
		    -m               Configure tmux.
		    -v               Configure vim.
		    -z               Configure zsh with prezto and starship.

		LEGAL
		    Created by Arthur <arthur@corenzan.com>. Licensed under public domain.
	EOF
}

init() {
	# Set defaults.
	hostname=""

	# Parse arguments.
	while getopts ":n:" option; do
		case "$option" in
		n)
			hostname="$OPTARG"
			;;
		:)
			fatal "Missing argument for option -$OPTARG."
			;;
		?)
			fatal "Unknown global option -$OPTARG. See -h for help."
			;;
		esac
	done

	# Clear arguments.
	shift $((OPTIND - 1))

	# Check if the hostname is set.
	if test -z "$hostname"; then
		fatal "Missing required option -n. See -h for help."
	fi

	# Require privilege, i.e. sudo.
	test "$(id -u)" -eq 0 || fatal "This command must be ran as root."

	# Let debconf know we won't interact.
	export DEBIAN_FRONTEND="noninteractive"

	# Get distro information.
	distro_id="$(lsb_release -is | tr '[:upper:]' '[:lower:]')"
	distro_name="$(lsb_release -cs)"
	arch="$(dpkg --print-architecture)"

	# Check distro compatibility.
	test "$distro_id" = "ubuntu" || test "$distro_id" = "debian" || fatal "Distro '$distro_id' isn't supported."

	# Check for required software.
	dependencies="apt-get update-locale lsb_release dpkg curl sysctl systemctl locale-gen chpasswd useradd groupadd usermod iptables ip6tables free"
	for dep in $dependencies; do
		if ! type "$dep" >/dev/null 2>&1; then
			fatal "$dep could not be found, which is a hard dependency along with: $dependencies."
		fi
	done

	# Add Docker repository to the source list.
	if ! test -f /etc/apt/sources.list.d/docker.list; then
		curl -fsSL "https://download.docker.com/linux/$distro_id/gpg" -o /etc/apt/trusted.gpg.d/docker.gpg
		echo "deb [arch=$arch] https://download.docker.com/linux/$distro_id $distro_name stable" > /etc/apt/sources.list.d/docker.list
	fi

	# Refresh repositories and upgrade installed packages.
	apt-get update
	apt-get upgrade

	# Set locale/encoding.
	export LANGUAGE=en_US.UTF-8
	export LC_ALL=en_US.UTF-8

	# Configure environment encoding.
	if ! locale -a | grep -q "$LANGUAGE"; then
		update-locale "LANGUAGE=$LANGUAGE" "LC_ALL=$LANGUAGE"
		locale-gen "$LANGUAGE"
	fi

	# Update hostname.
	if ! test "$(hostnamectl --static)" = "$hostname"; then
		hostnamectl set-hostname "$hostname"
	fi

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

	# Install common software.
	apt-get install -y build-essential apt-transport-https ca-certificates software-properties-common ntp git gnupg2 fail2ban unattended-upgrades docker-ce tmux zsh vim acl

	# Write custom Docker configuration.
	# https://docs.docker.com/engine/reference/commandline/dockerd/
	if ! test -f /etc/docker/daemon.json; then
		put /etc/docker/daemon.json <<-EOF
			{
			  "live-restore": true,
			  "log-driver": "json-file",
			  "log-opts": {
			    "max-size": "8m",
			    "max-file": "16"
			  }
			}
		EOF
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

	# Clean apt packages.
	apt-get clean
	apt-get autoremove

	# Create a new SSH group.
	if ! id -g remote >/dev/null 2>&1; then
		groupadd remote
	fi

	# Reset root password.
	password="$(random)"
	echo "root:$password" | chpasswd

	# Create apps user.
	if ! id apps >/dev/null 2>&1; then
		useradd -m apps
	fi

	# By setting the `setgid` bit, created files or directories will inherit group ownership.
	chmod g+s /home/apps

	# By setting this ACL, created files or directories will inherit group write permission.
	setfacl --set u::rwX,g::rwX,o::rX,d:u::rwX,d:g::rwX,d:o::rX /home/apps

	# Do not ask for password when sudoing.
	if ! test -f /etc/sudoers.d/nopasswd; then
		echo "%sudo ALL=(ALL:ALL) NOPASSWD:ALL" >/etc/sudoers.d/nopasswd
		chmod 440 /etc/sudoers.d/nopasswd
	fi

	# Configure the SSH server.
	if ! grep -q "Port 822" /etc/ssh/sshd_config; then
		put /etc/ssh/sshd_config <<-EOF
			# We omit ListenAddress so SSHD listens on all interfaces, both IPv4 and IPv6.

			# Supported HostKey algorithms by order of preference.
			HostKey /etc/ssh/ssh_host_rsa_key
			HostKey /etc/ssh/ssh_host_ed25519_key

			# Select the host key algorithms that the server is willing to use for authentication.
			HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

			# Select the signature algorithms that the server is willing to use for certificate authority (CA) signatures.
			CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

			# Select the key exchange algorithms that the server is willing to use for GSSAPI (Generic Security systemctl Program Interface) authentication. ssh
			GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-

			# Select the public key algorithms that the server is willing to accept for authentication.
			PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

			# Choose stronger Key Exchange algorithms.
			KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

			# Use modern ciphers for encryption.
			Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

			# Use MACs with larger tag sizes.
			MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

			# LogLevel VERBOSE logs user's key fingerprint on login. Needed to have a clear audit track of which key was using to log in.
			LogLevel VERBOSE

			# Don't let users set environment variables.
			PermitUserEnvironment no

			# Forwarding to X11 is considered insecure.
			X11Forwarding no

			# Disable forwarding.
			AllowStreamLocalForwarding no
			GatewayPorts no
			PermitTunnel no

			# Verify hostname matches IP.
			UseDNS yes

			# TCPKeepAlive is not encrypted.
			TCPKeepAlive no

			# Disable agent forwarding.
			AllowAgentForwarding no

			# Forbid root sessions.
			PermitRootLogin no

			# Password are insecure.
			PasswordAuthentication no

			# Allow users in 'remote' group to connect.
			# To add and remove users from the group, respectively:
			# - usermod -aG remote <username>
			# - gpasswd -d <username> remote
			AllowGroups remote

			# Drop idle clients.
			ClientAliveInterval 60
			ClientAliveCountMax 30

			# Drop if a client take too long to authenticate.
			LoginGraceTime 10

			# Log additional failures.
			MaxAuthTries 3

			# Limit connections from the same network.
			MaxSessions 2

			# Allow only one authentication at a time.
			MaxStartups 2

			# Silence is golden.
			DebianBanner no
			PrintMotd no

			# Change default port.
			Port 822
		EOF
	fi

	# The Diffie-Hellman algorithm is used by SSH to establish a secure connection.
	# The larger the moduli (key size) the stronger the encryption.
	# Remove all moduli smaller than 3072 bits.
	if ! test -f /etc/ssh/moduli.insecure; then
		cp -p /etc/ssh/moduli /etc/ssh/moduli.insecure
		awk '$5 >= 3071' /etc/ssh/moduli.insecure >/etc/ssh/moduli
	fi

	# Re-create existing host keys.
	rm -f /etc/ssh/ssh_host_*
	ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
	ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

	# Restart SSH server.
	systemctl restart ssh

	# Create swap space equivalent to the available memory.
	if ! test -f /swapfile; then
		ram=$(free -m | awk '/^Mem:/{print $2}')
		test "$ram" -lt 16384 || ram=16384
		dd if=/dev/zero of=/swapfile bs=1048576 count="$ram"
		chmod 600 /swapfile
		mkswap /swapfile
		swapon /swapfile
		backup /etc/fstab
		cat >>/etc/fstab <<-EOF
			/swapfile none swap sw 0 0
		EOF
	fi

	# Reduce swappiness (how likely the system is to swap memory).
	# vm.swappiness goes from 0 to 100, where 0 means the system will not swap memory unless it's absolutely necessary.
	if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
		backup /etc/sysctl.conf
		cat >>/etc/sysctl.conf <<-EOF
			vm.swappiness = 10
		EOF
		sysctl -p
	fi

	echo "Done."
}

register() {
	# Set defaults.
	username=""
	public_key=""

	# Parse arguments.
	while getopts ":u:k:" option; do
		case "$option" in
		u)
			username="$OPTARG"
			;;
		k)
			public_key="$OPTARG"
			;;
		:)
			fatal "Missing argument for option -$OPTARG."
			;;
		?)
			fatal "Unknown global option -$OPTARG. See -h for help."
			;;
		esac
	done

	# Clear arguments.
	shift $((OPTIND - 1))

	# Require privilege, i.e. sudo.
	test "$(id -u)" -eq 0 || fatal "This command must be ran as root."

	# Check for required software.
	dependencies="useradd usermod curl"
	for dep in $dependencies; do
		if ! type "$dep" >/dev/null 2>&1; then
			fatal "$dep could not be found, which is a hard dependency along with: $dependencies."
		fi
	done

	# Check if username is set.
	if test -z "$username"; then
		fatal "Username is required."
	fi

	# Check if user already exists.
	if id "$username" >/dev/null 2>&1; then
		fatal "User '$username' already exists."
	fi

	# Read public key from file or URL.
	if test "${public_key#http}" != "$public_key"; then
		public_key="$(curl -fsL --max-time 10 "$public_key")"
	elif test -f "$public_key"; then
		public_key="$(cat "$public_key")"
	else
		fatal "Public key could not be read from '$public_key'."
	fi

	# Create the new user.
	useradd -d "/home/$username" -m -s /bin/bash "$username"
	echo "$username:$(random)" | chpasswd
	usermod -aG sudo,remote,docker,apps "$username"

	# Setup RSA key for secure SSH authorization.
	# Use printf to prevent issues. e.g. is the key starts with a dash it could be interpreted as a flag.
	mkdir -p "/home/$username/.ssh"
	printf "%s\\n" "$public_key" >>"/home/$username/.ssh/authorized_keys"
	chown -R "$username:$username" "/home/$username/.ssh"
	chmod 700 "/home/$username/.ssh"
	chmod 600 "/home/$username/.ssh/authorized_keys"

	echo "Done."
}

tools() {
	# Set defaults.
	tmux=""
	vim=""
	zsh=""

	# Parse arguments.
	while getopts ":tvz" option; do
		case "$option" in
		t)
			tmux="tmux"
			;;
		v)
			vim="vim"
			;;
		z)
			zsh="zsh"
			;;
		:)
			fatal "Missing argument for option -$OPTARG."
			;;
		?)
			fatal "Unknown global option -$OPTARG. See -h for help."
			;;
		esac
	done

	# Clear arguments.
	shift $((OPTIND - 1))

	# Check we're not root.
	test "$(id -u)" -ne 0 || fatal "Tools should not be installed as root."

	# Check for required software.
	dependencies="git curl"
	for dep in $dependencies; do
		if ! type "$dep" >/dev/null 2>&1; then
			fatal "$dep could not be found, which is a hard dependency along with: $dependencies."
		fi
	done

	# Setup tmux.
	if test -n "${tmux=}"; then
		git clone --depth=1 https://github.com/gpakosz/.tmux.git "$HOME/.tmux"
		backup "$HOME/.tmux.conf"
		ln -s -f "$HOME/.tmux/.tmux.conf" "$HOME/.tmux.conf"
		cp "$HOME/.tmux/.tmux.conf.local" "$HOME/.tmux.conf.local"
	fi

	# Setup vim.
	if test -n "${vim=}"; then
		git clone --depth=1 https://github.com/amix/vimrc.git "$HOME/.vim_runtime"
		sh "$HOME/.vim_runtime/install_basic_vimrc.sh"
	fi

	# Setup zsh with prezto and starship.
	if test -n "${zsh=}"; then
		git clone --recursive https://github.com/sorin-ionescu/prezto.git "$HOME/.zprezto"
		find "$HOME/.zprezto/runcoms" -type f -not -name README.md | while read -r rcfile; do
			rcfile_name=".$(basename "$rcfile")"
			backup "$HOME/$rcfile_name"
			ln -s "$rcfile" "$HOME/$rcfile_name"
		done
		sudo chsh -s "$(which zsh)" "$(id -nu)"

		# Setup starship prompt.
		curl -sS https://starship.rs/install.sh | sh -s -- --yes
		mkdir -p "$HOME/.config"
		starship preset plain-text-symbols >"$HOME/.config/starship.toml"

		# Customize shell.
		sed "s/  'prompt'/  'syntax-highlighting' 'history-substring-search'/" "$HOME/.zpreztorc" | put "$HOME/.zpreztorc"
		sed "s/\(zstyle ':prezto:module:prompt' theme\)/#\1/" "$HOME/.zpreztorc" | put "$HOME/.zpreztorc"
		cat >>"$HOME/.zshrc" <<-EOF
			# starship prompt
			# https://starship.rs/
			eval "\$(starship init zsh)"

			CDPATH="/home/apps"

			# Aliases.
			alias g=git
			alias d=docker
			alias c="docker compose"
		EOF
	fi

	echo "Done."
}

# Print help if no arguments were passed.
if test $# -eq 0; then
	manual
	exit 1
fi

# Set defaults.
now="$(date +%s)"
debug=""
log="provision-$now.log"

# Parse arguments.
while getopts ":hxl:" option; do
	case "$option" in
	h)
		manual
		exit
		;;
	x)
		debug="true"
		;;
	l)
		log="$OPTARG"
		;;
	:)
		fatal "Missing argument for option -$OPTARG."
		;;
	?)
		fatal "Unknown global option -$OPTARG. See -h for help."
		;;
	esac
done

# Clear global options.
shift $((OPTIND - 1))

# Check if a command was specified.
if test $# -eq 0; then
	fatal "You must specify a command. See -h for help."
fi

# Check if command is valid.
if ! command -v "$1" >/dev/null 2>&1; then
	fatal "Unknown command '$1'. See -h for help."
fi

# Fix log output.
if test "$log" = "-"; then
	log="/dev/null"
fi

# Toggle debug mode.
test -z "$debug" || set -x

# Run the command.
"$@" | tee "$log" 2>&1
