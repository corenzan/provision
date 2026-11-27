#!/usr/bin/env bash
#
# Provision is an initialization script in Bash to help with
# the initial configuration required for a production-grade
# Debian-based server to host websites and applications.
#
# Created by Arthur <arthur@corenzan.com>, released on public domain.
#
# More at https://github.com/corenzan/provision.

# Halt on errors and undeclared variables.
set -ue

# Generate a random alphanumeric string of a given length.
random() {
	LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${1:-8}
}

# Save the original file, if it exists.
# cp -p preserves the file's mode, ownership, and timestamps.
backup() {
	if test -f "$1"; then
		cp -p "$1" "$1.$(date +%s)"
	fi
}

# Safely append to a file.
# We use a temporary file to avoid corrupting the file in case of error.
append() {
	temp="/tmp/$(random)"
	if test -f "$1"; then
		# cp -p preserves the original mode, ownership and timestamps.
		cp -p "$1" "$temp"
	fi
	cat >>"$temp"
	backup "$1"
	mv "$temp" "$1"
}

# Safely replace file contents.
# We use a temporary file to avoid corrupting the file in case of error.
put() {
	temp="/tmp/$(random)"
	if test -f "$1"; then
		# cp -p preserves the original mode, ownership and timestamps.
		cp -p "$1" "$temp"
	fi
	cat >"$temp"
	backup "$1"
	mv "$temp" "$1"
}

# Check for required dependencies.
depends() {
	for dep in "$@"; do
		if ! command -v "$dep" >/dev/null 2>&1; then
			fatal "$dep is required and could not be found."
		fi
	done
}

# Fetch content from a URL.
# -f: fail silently on server errors.
# -s: silent mode.
# -S: show error messages if the request fails.
# --max-time 10: set a time limit of 10 seconds for the request.
fetch() {
	curl -fsSL --max-time 30 "$@"
}

# Print an error message and exit.
fatal() {
	echo "provision: $1" >&2
	exit 1
}

# Print the manual.
manual() {
	cat <<-EOF >&2
		SYNOPSIS
		    Configure a Debian based linux server.

		USAGE
		    provision.sh [options]

		OPTIONS
		    -h                          Print out this manual.
		    -x                          Print out each command for debugging. Optional.
		    -l <file>                   Log output to file. Defaults to provision-<timestamp>.log. Use '-' to disable.
		    -i                          Initialize server configuration. Implies -r. Optional.
		    -r                          Create the administrator given by -u. Optional.
		    -n <hostname>               Server's hostname. Required if -i is set.
		    -u <username>               Administrator's username. Required if -r is set.
		    -k <public key>             File path or URL to administrator's public key. Required if -r is set.

		LEGAL
		    Created by Arthur <arthur@corenzan.com>. Licensed under public domain.
	EOF
}

initialize() {
	# Check if the effective user ID is 0 (root).
	test "$(id -u)" -eq 0 || fatal "This command must be ran as root."

	# Check if the hostname option is set.
	if test -z "$hostname"; then
		fatal "Missing required option for hostname. See -h for help."
	fi

	# Check for required software.
	depends curl update-locale locale-gen iptables ip6tables

	# Get distro information from os-release(5).
	# ID: distributor ID, always lowercase (e.g., ubuntu, debian).
	# VERSION_CODENAME: codename (e.g., focal, bookworm).
	# dpkg --print-architecture: print the system architecture (e.g., amd64, arm64).
	. /etc/os-release

	# Check distro compatibility.
	test "${ID:-}" = "debian" || test "${ID_LIKE:-}" = "debian" || fatal "Distro '${ID:-}' isn't supported."
	test -n "${VERSION_CODENAME:-}" || fatal "Couldn't determine the distro codename. See os-release(5)."

	# Install the official Docker GPG key.
	if ! test -f /etc/apt/keyrings/docker.asc; then
		install -m 0755 -d /etc/apt/keyrings
		fetch "https://download.docker.com/linux/$ID/gpg" | put /etc/apt/keyrings/docker.asc
		chmod a+r /etc/apt/keyrings/docker.asc
	fi

	# Add the official Docker repository to the sources list.
	if ! test -f /etc/apt/sources.list.d/docker.sources; then
		put /etc/apt/sources.list.d/docker.sources <<-EOF
			Types: deb
			URIs: https://download.docker.com/linux/$ID
			Suites: $VERSION_CODENAME
			Components: stable
			Architectures: $(dpkg --print-architecture)
			Signed-By: /etc/apt/keyrings/docker.asc
		EOF
	fi

	# This prevents debconf from prompting for user input during package installation/configuration.
	export DEBIAN_FRONTEND="noninteractive"

	# Refresh repositories and upgrade installed packages.
	apt-get update
	apt-get upgrade -y

	# Ensure the en_US.UTF-8 locale is generated.
	if ! locale -a | grep -qi '^en_US\.utf-\?8$'; then
		locale-gen en_US.UTF-8
	fi

	# Update the system's default locale if it isn't already set to en_US.UTF-8.
	if ! grep -q '^LANG=en_US\.UTF-8$' /etc/default/locale 2>/dev/null; then
		update-locale LANG=en_US.UTF-8
	fi
	export LANG=en_US.UTF-8

	# Set the system's static hostname.
	if ! test "$(hostnamectl --static)" = "$hostname"; then
		hostnamectl set-hostname "$hostname"
	fi

	# Prevent cloud-init from overwriting the hostname during reboots.
	if test -d /etc/cloud/cloud.cfg.d; then
		put /etc/cloud/cloud.cfg.d/99_preserve_hostname.cfg <<-EOF
			preserve_hostname: true
		EOF
	fi

	for iptables in iptables ip6tables; do
		# Clear rules.
		# -F: flush all rules in all chains.
		# -t nat -F: flush all rules in the NAT table.
		# -P INPUT ACCEPT: set the default policy for the INPUT chain to ACCEPT (temporarily).
		# This is done to start with a clean slate before adding our firewall rules.
		"$iptables" -F
		"$iptables" -t nat -F
		"$iptables" -P INPUT ACCEPT
		"$iptables" -P OUTPUT ACCEPT
		"$iptables" -P FORWARD ACCEPT

		# Loopback (covers 127.0.0.1 and ::1, including local Docker daemon communication).
		"$iptables" -A INPUT -i lo -j ACCEPT
		"$iptables" -A OUTPUT -o lo -j ACCEPT

		# Allow established and related traffic so active SSH sessions are never dropped.
		"$iptables" -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

		# Allow ICMP / ICMPv6 for path MTU discovery and neighbor discovery.
		if test "$iptables" = "iptables"; then
			"$iptables" -A INPUT -p icmp -j ACCEPT
		else
			"$iptables" -A INPUT -p icmpv6 -j ACCEPT

			# Allow DHCPv6 client replies.
			"$iptables" -A INPUT -p udp --dport 546 -j ACCEPT
		fi

		# Allow public HTTP, HTTPS, and custom SSH port.
		"$iptables" -A INPUT -p tcp --dport 80 -j ACCEPT
		"$iptables" -A INPUT -p tcp --dport 443 -j ACCEPT
		"$iptables" -A INPUT -p tcp --dport 822 -j ACCEPT

		# Default-deny inbound traffic to the host.
		"$iptables" -A INPUT -j DROP
	done

	# Pre-create DOCKER-USER so we can harden container port exposure before Docker starts.
	# Blocks external access to published container ports (-p 8080:80) unless bound to localhost or routed through a reverse proxy, while allowing container-to-internet and established replies.
	# ip6tables parity isn't needed as long as Docker isn't using IPv6.
	iptables -N DOCKER-USER

	# Allow established and related traffic.
	iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

	# Allow traffic from the default Docker bridge network (docker0).
	iptables -A DOCKER-USER -i docker0 -j RETURN

	# Allow traffic from custom Docker bridge networks.
	iptables -A DOCKER-USER -i br-+ -j RETURN

	# Allow traffic to public HTTP and HTTPS ports.
	iptables -A DOCKER-USER -p tcp --ctorigdstport 80 -j RETURN
	iptables -A DOCKER-USER -p tcp --ctorigdstport 443 -j RETURN

	# Drop all other traffic to enforce the rules above.
	iptables -A DOCKER-USER -j DROP

	# Persist iptables configuration BEFORE installing Docker and fail2ban.
	apt-get install -y iptables-persistent
	netfilter-persistent save

	# Install common software.
	# build-essential: basic development tools (compiler, make, etc.).
	# ca-certificates: common CA certificates for SSL/TLS.
	# chrony: for time synchronization.
	# git: version control system.
	# gnupg2: GNU Privacy Guard for encryption and signing.
	# fail2ban: intrusion prevention software that monitors log files and bans IPs showing malicious signs.
	# unattended-upgrades: automatically installs security updates.
	# docker-ce: Docker Community Edition.
	# docker-ce-cli: command-line interface for Docker.
	# containerd.io: container runtime used by Docker.
	# docker-buildx-plugin: Docker Buildx plugin for building multi-platform images.
	# docker-compose-plugin: Docker Compose plugin for managing multi-container applications.
	# tmux: terminal multiplexer.
	# zsh: alternative to bash.
	# fish: alternative to bash.
	# vim: text editor.
	# acl: Access Control List utilities for finer-grained file permissions.
	# btop: resource monitor for system performance.
	apt-get install -y build-essential ca-certificates chrony git gnupg2 fail2ban unattended-upgrades docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin tmux zsh fish vim acl btop

	# Configure fail2ban to watch our custom SSH port.
	put /etc/fail2ban/jail.d/sshd.local <<-EOF
		[sshd]
		port = 822
	EOF
	systemctl restart fail2ban

	# Download and run the Starship installer script.
	fetch https://starship.rs/install.sh | sh -s -- --yes

	# Write custom Docker configuration.
	# https://docs.docker.com/engine/reference/commandline/dockerd/
	# live-restore: allows containers to keep running during daemon upgrades or restarts.
	# log-driver: specifies the log driver for containers.
	# max-size: maximum size of a log file before it's rotated.
	# max-file: maximum number of log files to keep.
	if ! test -f /etc/docker/daemon.json; then
		put /etc/docker/daemon.json <<-EOF
			{
			  "live-restore": true,
			  "log-driver": "json-file",
			  "log-opts": {
			    "max-size": "16m",
			    "max-file": "4"
			  }
			}
		EOF

		# Restart the Docker service to apply the new configuration.
		systemctl restart docker
	fi

	# apt-get clean: remove downloaded package files (.deb) from the local repository.
	# apt-get autoremove: remove packages that were automatically installed to satisfy dependencies for other packages and are now no longer needed.
	apt-get clean
	apt-get autoremove -y

	# The group 'remote' will be used to control SSH access.
	if ! id -g remote >/dev/null 2>&1; then
		groupadd remote
	fi

	# A dedicated user for running applications, separate from administrative users.
	if ! id apps >/dev/null 2>&1; then
		# -m creates the home directory.
		useradd -m apps

		# Allow 'apps' user to access SSH and Docker.
		usermod -aG remote,docker apps
	fi

	# Setup SSH for the 'apps' user.
	install -m 700 -o apps -g apps -d /home/apps/.ssh
	install -m 600 -o apps -g apps /dev/null /home/apps/.ssh/authorized_keys

	# By setting the 'setgid' bit, created files or directories will inherit group ownership.
	# This is useful for shared directories where multiple users in the 'apps' group might create files.
	chmod g+s /home/apps

	# By setting this ACL, created files or directories will inherit group write permission.
	# u::rwX: user (owner) gets read, write, execute/search.
	# g::rwX: group gets read, write, execute/search.
	# o::rX: others get read, execute/search.
	# d:u::rwX, d:g::rwX, d:o::rX: default ACLs for new files/directories created within /home/apps.
	setfacl --set u::rwX,g::rwX,o::rX,d:u::rwX,d:g::rwX,d:o::rX /home/apps

	# Allows users in the 'sudo' group to run commands as root without entering a password.
	# This is a convenience but should be used with caution and awareness of security implications.
	if ! test -f /etc/sudoers.d/nopasswd; then
		echo "%sudo ALL=(ALL:ALL) NOPASSWD:ALL" >/etc/sudoers.d/nopasswd
		chmod 440 /etc/sudoers.d/nopasswd
	fi

	# Configure the SSH server.
	# Design: the only ways in are a publickey shell and sftp. No passwords, and
	# no forwarding, so there is nothing to pivot through once inside.
	#
	# Applied only when the custom port isn't already set, which serves as the
	# marker that this script hasn't configured sshd yet. On an already
	# provisioned host, edits to this block have no effect.
	if ! grep -q "Port 822" /etc/ssh/sshd_config; then
		put /etc/ssh/sshd_config <<-EOF
			# ListenAddress is deliberately omitted so sshd listens on all
			# interfaces, IPv4 and IPv6 alike.

			# One host key only; see the ssh-keygen call below, which also
			# replaces whatever keys the image or installer generated.
			HostKey /etc/ssh/ssh_host_ed25519_key

			# Host keys offered to clients, ed25519 only, so an RSA key is
			# never generated or exposed. sk-* is for FIDO/U2F hardware keys.
			HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519

			# Signature algorithms accepted from a certificate authority.
			# Inert until TrustedUserCAKeys points at a CA.
			CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519

			# User keys accepted. Ed25519 only: any account still holding an
			# RSA key cannot log in until ssh-rsa is added here.
			PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519

			# Post-quantum hybrid KEX first, classical curve25519 as fallback.
			KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256

			# All AEAD, so integrity comes from the cipher and no MAC list is needed.
			Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

			# Logs the fingerprint of the key used, so a login can be traced to a
			# specific key rather than just a user.
			LogLevel VERBOSE

			# Blocks authorized_keys environment= from injecting PATH,
			# LD_PRELOAD and friends into the session.
			PermitUserEnvironment no

			# Every forwarding type is off; there is no pivoting path once inside.
			# X11 is a rich protocol with a poor security record.
			X11Forwarding no

			# Blocks reaching local sockets such as docker.sock, which the apps
			# user can reach given its membership in the docker group.
			AllowStreamLocalForwarding no

			# Only takes effect while a forwarding is enabled; keeps it bound to
			# loopback if one is ever turned back on.
			GatewayPorts no

			# No tunnel devices, so no TUN/TAP based VPN over SSH.
			PermitTunnel no

			# Off because hostbased authentication is off: the lookup only adds
			# latency under attacker-controlled PTR records.
			UseDNS no

			# TCPKeepAlive is unencrypted and its packets can be spoofed;
			# ClientAlive* below run inside the encrypted channel instead.
			TCPKeepAlive no

			# sftp and scp are the only file transfer paths, and scp also needs
			# this subsystem on modern OpenSSH.
			Subsystem sftp /usr/lib/openssh/sftp-server

			# Upstream defaults to yes for both; set explicitly to pin intent.
			AllowTCPForwarding no
			AllowAgentForwarding no

			# Root has no path in at all, not even with a key.
			PermitRootLogin no

			# PAM, not just for auth: it is what creates the systemd user session
			# and applies cgroup, resource and environment setup on login.
			UsePAM yes

			# Publickey is required and sufficient. To add a second factor later,
			# append ,keyboard-interactive here rather than re-enabling passwords.
			AuthenticationMethods publickey

			# Redundant with the line above, kept to cover edge cases.
			PasswordAuthentication no

			# With UsePAM yes, keyboard-interactive is a PAM path that could
			# bypass the publickey-only requirement.
			KbdInteractiveAuthentication no

			# Only members of the remote group get in, even with a valid key.
			# Combined with Port 822 below, this is a lockout risk: verify group
			# membership and keep console access until a new session is proven.
			# - usermod -aG remote <username>
			# - gpasswd -d <username> remote
			AllowGroups remote

			# Drops dead clients after ~10 minutes of unanswered keep-alives,
			# freeing a slot that would otherwise sit reserved.
			ClientAliveInterval 60
			ClientAliveCountMax 10

			# Caps how long an unauthenticated connection can sit, so a slow
			# handshake cannot hold a slot indefinitely.
			LoginGraceTime 60

			# Halves the per-connection brute-force rate at negligible cost.
			MaxAuthTries 3

			# One connection is enough for normal use; this bounds multiplexing.
			MaxSessions 10

			# At 10 pending unauthenticated connections, start dropping 30% of
			# new ones, hard cap 60. PerSourceMaxStartups keeps a single host
			# from consuming the whole global pool.
			MaxStartups 10:30:60
			PerSourceMaxStartups 3

			# Don't advertise the distro or version on connect.
			DebianBanner no

			# MOTD is noise on the wire; login messages belong to the shell or the
			# authentication flow, not to sshd.
			PrintMotd no

			# A non-standard port only reduces automated scan noise. The socket
			# unit below is what actually makes sshd listen here, and both have
			# to agree.
			Port 822
		EOF
	fi

	# The Diffie-Hellman algorithm is used by SSH to establish a secure connection.
	# The larger the moduli (key size) the stronger the encryption.
	# Remove all moduli smaller than 3072 bits from /etc/ssh/moduli.
	# This helps protect against Logjam-type attacks by ensuring strong DH parameters.
	if ! test -f /etc/ssh/moduli.insecure; then
		cp -p /etc/ssh/moduli /etc/ssh/moduli.insecure
		awk '$5 >= 3071' /etc/ssh/moduli.insecure >/etc/ssh/moduli
	fi

	# Re-create existing host keys.
	# -t ed25519: only key type generated; the sshd_config above advertises
	# nothing else, so an RSA host key would just be dead weight.
	# -N "": sets an empty passphrase for the key.
	rm -f /etc/ssh/ssh_host_*
	ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

	# Since Ubuntu Server 24.04, SSH server uses a socket configuration and doesn't honor the Port setting in sshd_config.
	if ! test -f /etc/systemd/system/ssh.socket.d/port.conf; then
		mkdir -p /etc/systemd/system/ssh.socket.d
		put /etc/systemd/system/ssh.socket.d/port.conf <<-EOF
			[Socket]
			ListenStream=
			ListenStream=822
		EOF
	fi

	# Validate the new SSH configuration before applying it.
	sshd -t
	systemctl daemon-reload
	systemctl restart ssh.socket

	# Allocate swap space equivalent to the available memory up to 16GB.
	# Swap space is used when the system runs out of physical RAM.
	if test -z "$(swapon --show --noheadings)"; then
		# Get available RAM in MB.
		ram=$(free -m | awk '/^Mem:/{print $2}')

		# Cap swap size at 16GB to avoid excessive storage usage.
		test "$ram" -lt 16384 || ram=16384

		# Try to use fallocate if available (much faster), otherwise use dd.
		if ! fallocate -l "${ram}M" /swap.img; then
			truncate -s 0 /swap.img
			chattr +C /swap.img
			dd if=/dev/zero of=/swap.img bs=1M count="$ram" status=progress
		fi

		# Set restrictive permissions on the swap file.
		chmod 600 /swap.img

		# Set up the swap file as a Linux swap area.
		mkswap /swap.img

		# Enable the swap file for immediate use.
		swapon /swap.img

		# Add an entry to /etc/fstab to make the swap file persistent across reboots.
		append /etc/fstab <<-EOF
			/swap.img none swap sw 0 0
		EOF
	fi

	# Reduce how likely the system is to swap memory.
	# Swappiness ranges from 0 (avoid swapping as much as possible) to 100 (will swap aggressively).
	# A value of 10 is a common recommendation for servers, prioritizing keeping applications in RAM.
	if ! test -f /etc/sysctl.d/99-swappiness.conf; then
		put /etc/sysctl.d/99-swappiness.conf <<-EOF
			vm.swappiness = 10
		EOF

		# Apply sysctl changes without rebooting.
		sysctl --system
	fi
}

# Validate everything register() needs, without changing the system, so a
# bad option or unreachable key fails before initialize() or register() runs.
pre_register() {
	# Require privilege, i.e. sudo.
	test "$(id -u)" -eq 0 || fatal "This command must be ran as root."

	# Check if username is set.
	if test -z "$username"; then
		fatal "Username is required."
	fi

	# Check if the user already exists.
	if id "$username" >/dev/null 2>&1; then
		fatal "User '$username' already exists."
	fi

	# Check for required non-standard commands.
	depends curl

	# Check the public key is obtainable, resolving it from a file or URL.
	# The construct "${key#http}" removes "http" from the beginning of $key.
	# If it's different from the original, it means $key started with "http".
	# If it's a regular file (-f), we just read its contents.
	if test "${key#http}" != "$key"; then
		key="$(fetch "$key")"
	elif test -f "$key"; then
		key="$(cat "$key")"
	else
		fatal "Public key could not be read from '$key'."
	fi

	if ! cat "$key" | ssh-keygen -lf - >/dev/null 2>&1; then
	    fatal "Public key is invalid."
	fi
}

register() {
	# Create the new user.
	# -d /home/$username: set the user's home directory.
	# -m: create the home directory if it doesn't exist.
	# -s /bin/bash: set the default login shell to bash.
	# No password is set, so the account stays locked and is only reachable
	# with the public key added below.
	useradd -d "/home/$username" -m -s /bin/bash "$username"

	# Add the user to relevant groups:
	# sudo: allows running commands with root privileges (via sudo).
	# remote: custom group designated for SSH access in the sshd_config.
	# docker: allows running docker commands without needing sudo.
	# apps: custom group for users managing applications in /home/apps.
	usermod -aG sudo,remote,docker,apps "$username"

	# Setup SSH key for secure authorization.
	# Create the .ssh directory in the user's home if it doesn't exist (-p creates parent dirs if needed).
	mkdir -p "/home/$username/.ssh"

	# Use printf to append the public key to authorized_keys.
	# This is generally safer than echo, especially if the key string might start with a dash or contain backslashes.
	# "%s\\n" ensures the key is printed as a string followed by a newline.
	printf "%s\\n" "$key" >>"/home/$username/.ssh/authorized_keys"

	# Set correct ownership and permissions for the .ssh directory and authorized_keys file.
	# This is crucial for SSH key authentication to work; SSH is very picky about these permissions.
	# chown -R recursively sets owner and group to the new user.
	chown -R "$username:$username" "/home/$username/.ssh"

	# .ssh directory should be 700 (drwx------): only owner can read, write, and execute (access).
	chmod 700 "/home/$username/.ssh"

	# authorized_keys file should be 600 (-rw-------): only owner can read and write.
	chmod 600 "/home/$username/.ssh/authorized_keys"
}

main() {
	# If $mode is 0, it means no command options were specified.
	if test $mode -eq 0; then
		fatal "No command option was specified: -i or -r. See -h for help."
	fi

	# If bit 2 is set, the register command was requested. Validate its
	# inputs first, so it fails before either command makes any changes.
	if test $((mode & 2)) -ne 0; then
		pre_register
	fi

	# If bit 1 is set, the initialize command was requested.
	if test $((mode & 1)) -ne 0; then
		initialize
	fi

	# If bit 2 is set, the register command was requested.
	if test $((mode & 2)) -ne 0; then
		register
	fi
}

# Print help if no arguments were passed.
# $# is the number of positional parameters (arguments).
if test $# -eq 0; then
	manual
	exit 1
fi

# Set defaults.
now="$(date +%s)"
debug=""
log="provision-$now.log"
hostname=""
username=""
key=""
mode=0

# Parse global arguments.
while getopts ":hxl:irn:u:k:" option; do
	case "$option" in
	h)
		manual
		exit
		;;
	x)
		debug="-x"
		;;
	l)
		log="$OPTARG"
		;;
	i)
		# Initialize implies register.
		mode=$((mode | 1 | 2))
		;;
	n)
		hostname="$OPTARG"
		;;
	r)
		mode=$((mode | 2))
		;;
	u)
		username="$OPTARG"
		;;
	k)
		key="$OPTARG"
		;;
	:)
		fatal "Missing argument for option -$OPTARG."
		;;
	?)
		fatal "Unknown global option -$OPTARG. See -h for help."
		;;
	esac
done

# Shift positional parameters to clear parsed arguments.
shift $((OPTIND - 1))

# If log file is specified as '-', redirect to /dev/null (disable logging).
if test "$log" = "-"; then
	log="/dev/null"
fi

# Toggle debug mode.
# `set -x` causes the shell to print each command before it is executed.
if test -n "$debug"; then
	set -x
fi

# Run the requested commands redirecting both stdout and stderr to the log file.
main 2>&1 | tee "$log"
