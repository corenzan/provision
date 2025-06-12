#!/usr/bin/env sh

# Halt on errors and undeclared variables.
set -ue

# Generate a random string of 64 bytes.
random() {
	tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64
}

# Save the original file, if it exists.
# cp -p preserves the file's mode, ownership, and timestamps.
save() {
	if test -f "$1"; then
		cp -p "$1" "$1.$now"
	fi
}

# Safely append to a file.
# We use a temporary file to avoid corrupting the file in case of error.
append() {
	temp="$(mktemp)"
	if test -f "$1"; then
		cat "$1" >"$temp"
	fi
	cat >>"$temp"
	save "$1"
	mv "$temp" "$1"
}

# Safely replace file contents.
# We use a temporary file to avoid corrupting the file in case of error.
put() {
	temp="$(mktemp)"
	cat >"$temp"
	save "$1"
	mv "$temp" "$1"
}

# Fetch some content from a URL.
# -s: silent mode, no progress or results.
# -S: show error messages if the request fails.
# --max-time 10: set a time limit of 10 seconds for the request.
fetch() {
	curl -fsSL --max-time 10 "$@" 
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
		    Configure a Debian based linux server.

		USAGE
		    provision.sh [options]

		OPTIONS
		    -h               Print out this manual.
		    -x               Print out each command for debugging. Optional.
		    -l <file>        Log output to file. Defaults to provision-<timestamp>.log. Use '-' to disable.
		    -i               Initialize server configuration. Optional.
		    -r               Create the administrator given by -u. Optional.
		    -t               Configure tools for the administrator given by -u. Optional.
		    -n <hostname>    Server's hostname. Required if -i is set.
		    -u <username>    Administrator's username. Required if either -r or -t are set.
		    -k <public key>  File path or URL to administrator's public key. Required if -r is set.

		LEGAL
		    Created by Arthur <arthur@corenzan.com>. Licensed under public domain.
	EOF
}

initialize() {
	# Checks if the effective user ID is 0 (root).
	test "$(id -u)" -eq 0 || fatal "This command must be ran as root."

	# Check if the hostname option is set.
	if test -z "$hostname"; then
		fatal "Missing required option for hostname. See -h for help."
	fi

	# Get distro information.
	# lsb_release -is: prints distributor ID (e.g., Ubuntu, Debian) in lowercase.
	# lsb_release -cs: prints codename (e.g., focal, buster).
	# dpkg --print-architecture: prints the system architecture (e.g., amd64, arm64).
	distro_id="$(lsb_release -is | tr '[:upper:]' '[:lower:]')"
	distro_name="$(lsb_release -cs)"
	arch="$(dpkg --print-architecture)"

	# Check distro compatibility.
	# This script is designed for Ubuntu or Debian.
	test "$distro_id" = "ubuntu" || test "$distro_id" = "debian" || fatal "Distro '$distro_id' isn't supported."

	# Check for required software.
	# These are essential commands used throughout the script.
	dependencies="apt-get update-locale lsb_release dpkg curl sysctl systemctl locale-gen chpasswd useradd groupadd usermod iptables ip6tables free"
	for dep in $dependencies; do
		if ! command -v "$dep" >/dev/null 2>&1; then
			fatal "$dep could not be found, which is a hard dependency along with: $dependencies."
		fi
	done

	# Add Docker official repository to the source list.
	if ! test -f /etc/apt/sources.list.d/docker.list; then
		# Download Docker's official GPG key to verify package integrity.
		fetch "https://download.docker.com/linux/$distro_id/gpg" -o /etc/apt/trusted.gpg.d/docker.asc
		# Fix permissions on the GPG key file.
		# chmod a+r /etc/apt/keyrings/docker.asc
		# Add the Docker repository URL to APT's sources.
		echo "deb [arch=$arch] https://download.docker.com/linux/$distro_id $distro_name stable" > /etc/apt/sources.list.d/docker.list
	fi

	# This prevents debconf from prompting for user input during package installation/configuration.
	export DEBIAN_FRONTEND="noninteractive"

	# Refresh repositories and upgrade installed packages.
	# apt-get update: refreshes the local package list from repositories.
	# apt-get upgrade: upgrades all currently installed packages to their newest versions.
	apt-get update
	apt-get upgrade -y

	# Set locale/encoding.
	# en_US.UTF-8 is a widely compatible locale supporting English and UTF-8 character encoding.
	export LANGUAGE=en_US.UTF-8
	export LC_ALL=en_US.UTF-8

	# Ensures the chosen locale is available and set system-wide.
	if ! locale -a | grep -q "$LANGUAGE"; then
		update-locale "LANGUAGE=$LANGUAGE" "LC_ALL=$LANGUAGE"
		locale-gen "$LANGUAGE"
	fi

	# Sets the system's static hostname.
	if ! test "$(hostnamectl --static)" = "$hostname"; then
		hostnamectl set-hostname "$hostname"
	fi

	# Clear rules for IPv4.
	# -F: Flushes all rules in all chains.
	# -t nat -F: Flushes all rules in the NAT table.
	# -P INPUT ACCEPT: Sets the default policy for the INPUT chain to ACCEPT (temporarily).
	# Similar policies are set for OUTPUT and FORWARD chains.
	# This is done to start with a clean slate before adding our firewall rules.
	iptables -F
	iptables -t nat -F
	iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD ACCEPT

	# Same as above, but for IPv6.
	ip6tables -F
	ip6tables -t nat -F
	ip6tables -P INPUT ACCEPT
	ip6tables -P OUTPUT ACCEPT
	ip6tables -P FORWARD ACCEPT

	# Accept anything from/to loopback interface in IPv4.
	# The loopback interface (lo) is used for local communication within the host.
	iptables -A INPUT -i lo -j ACCEPT
	iptables -A OUTPUT -o lo -j ACCEPT

	# Accept anything from/to loopback interface in IPv6.
	ip6tables -A INPUT -i lo -j ACCEPT
	ip6tables -A OUTPUT -o lo -j ACCEPT

	# This allows ongoing connections (e.g., an active SSH session) to continue.
	# RELATED: packets starting a new connection related to an existing one (e.g. FTP data transfer).
	# ESTABLISHED: packets part of an already existing connection.
	iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

	# Allow ICMP calls in both IPv4 and IPv6 for proper network operation (see http://shouldiblockicmp.com).
	iptables -A INPUT -p icmp -j ACCEPT
	ip6tables -A INPUT -p icmpv6 -j ACCEPT

	# Allow dockerd communication in IPv4.
	# Port 2375 is the default unencrypted Docker daemon port.
	# This rule restricts access to localhost (127.0.0.1) for security.
	iptables -A INPUT -s 127.0.0.1 -p tcp --dport 2375 -j ACCEPT

	# Similar to IPv4, but for the IPv6 loopback address (::1).
	ip6tables -A INPUT -s ::1 -p tcp --dport 2375 -j ACCEPT

	# Port 80 for HTTP, 443 for HTTPS, and 822 for SSH (custom port).
	iptables -A INPUT -p tcp --dport 80 -j ACCEPT
	iptables -A INPUT -p tcp --dport 443 -j ACCEPT
	iptables -A INPUT -p tcp --dport 822 -j ACCEPT

	# Allow incoming traffic for HTTP, HTTPS and SSH (custom port) in IPv6.
	ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
	ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
	ip6tables -A INPUT -p tcp --dport 822 -j ACCEPT

	# This is the default-deny policy for the INPUT chain.
	# Any traffic not explicitly allowed by previous rules will be dropped.
	iptables -A INPUT -j DROP
	ip6tables -A INPUT -j DROP

	# Logs dropped packets (and any other packets reaching the end of INPUT/FORWARD chains) to help with debugging firewall rules.
	# --log-tcp-options: Logs TCP header options.
	# --log-prefix: Adds a prefix to log messages for easier identification.
	iptables -A INPUT -j LOG --log-tcp-options --log-prefix "[iptables] "
	iptables -A FORWARD -j LOG --log-tcp-options --log-prefix "[iptables] "
	ip6tables -A INPUT -j LOG --log-tcp-options --log-prefix "[ip6tables] "
	ip6tables -A FORWARD -j LOG --log-tcp-options --log-prefix "[ip6tables] "

	# Pipe iptables log to its own file.
	# Configures rsyslog to write messages containing "[iptables] " to /var/log/iptables.log.
	# & stop: Prevents these messages from being written to other log files (e.g., /var/log/syslog).
	cat > /etc/rsyslog.d/10-iptables.conf <<-EOF
		:msg, contains, "[iptables] " -/var/log/iptables.log
		& stop
	EOF

	# Pipe ip6tables log to its own file.
	cat > /etc/rsyslog.d/10-ip6tables.conf <<-EOF
		:msg, contains, "[ip6tables] " -/var/log/ip6tables.log
		& stop
	EOF

	# Restarts rsyslog to apply the new logging rules.
	service rsyslog restart

	# Configures logrotate to manage /var/log/iptables.log:
	# rotate 30: Keep 30 old log files.
	# daily: Rotate daily.
	# missingok: Don't error if the log file is missing.
	# notifempty: Don't rotate if the log file is empty.
	# delaycompress: Delay compression of the previous log file to the next rotation cycle.
	# compress: Compress rotated log files.
	# postrotate: Command to run after rotation (reloads rsyslog).
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

	# Same configuration as for ip6tables logs.
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
	# build-essential: Basic development tools (compiler, make, etc.).
	# apt-transport-https: Allows APT to use HTTPS repositories.
	# ca-certificates: Common CA certificates for SSL/TLS.
	# software-properties-common: Utilities for managing software repositories (e.g., add-apt-repository).
	# ntp: Network Time Protocol client for time synchronization.
	# git: Version control system.
	# gnupg2: GNU Privacy Guard for encryption and signing.
	# fail2ban: Intrusion prevention software that monitors log files and bans IPs showing malicious signs.
	# unattended-upgrades: Automatically installs security updates.
	# docker-ce: Docker Community Edition.
	# tmux: Terminal multiplexer.
	# zsh: Z shell, an alternative to bash.
	# vim: Text editor.
	# acl: Access Control List utilities for finer-grained file permissions.
	# btop: Resource monitor for system performance.
	apt-get install -y build-essential apt-transport-https ca-certificates software-properties-common ntp git gnupg2 fail2ban unattended-upgrades docker-ce tmux zsh vim acl btop

	# Download and run the starship installer script.
	fetch https://starship.rs/install.sh | sh -s -- --yes

	# Write custom Docker configuration.
	# https://docs.docker.com/engine/reference/commandline/dockerd/
	# live-restore: Allows containers to keep running during daemon upgrades or restarts.
	# log-driver: Specifies the log driver for containers.
	# max-size: Maximum size of a log file before it's rotated.
	# max-file: Maximum number of log files to keep.
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
	fi

	# Save iptables configuration, but only after installing new packages, since they might have modified the rules.
	# iptables-save outputs the current iptables rules to stdout.
	iptables-save > /etc/iptables.conf
	ip6tables-save > /etc/ip6tables.conf

	# Load iptables config when network device is up.
	# Creates a script in /etc/network/if-up.d/ to restore iptables rules when a network interface comes up.
	# This ensures firewall rules persist after a reboot.
	cat > /etc/network/if-up.d/iptables <<-EOF
		#!/usr/bin/env sh
		iptables-restore < /etc/iptables.conf
	EOF
	chmod +x /etc/network/if-up.d/iptables

	# Load ip6tables config when network device is up.
	cat > /etc/network/if-up.d/ip6tables <<-EOF
		#!/usr/bin/env sh
		ip6tables-restore < /etc/ip6tables.conf
	EOF
	chmod +x /etc/network/if-up.d/ip6tables

	# apt-get clean: Removes downloaded package files (.deb) from the local repository.
	# apt-get autoremove: Removes packages that were automatically installed to satisfy dependencies for other packages and are now no longer needed.
	apt-get clean 
	apt-get autoremove -y

	# The group 'remote' will be used to control SSH access.
	if ! id -g remote >/dev/null 2>&1; then
		groupadd remote
	fi

	# Generates a random password for the root user.
	# It's good practice to change default/known passwords, even if root login via SSH is disabled.
	# tee /dev/tty: print out the credentials.
	echo "root:$(random)" | tee /dev/tty | chpasswd

	# A dedicated user for running applications, separate from administrative users.
	if ! id apps >/dev/null 2>&1; then
		useradd -m apps # -m creates the home directory.
	fi

	# By setting the 'setgid' bit, created files or directories will inherit group ownership.
	# This is useful for shared directories where multiple users in the 'apps' group might create files.
	chmod g+s /home/apps

	# By setting this ACL, created files or directories will inherit group write permission.
	# u::rwX: User (owner) gets read, write, execute/search.
	# g::rwX: Group gets read, write, execute/search.
	# o::rX: Others get read, execute/search.
	# d:u::rwX, d:g::rwX, d:o::rX: Default ACLs for new files/directories created within /home/apps.
	setfacl --set u::rwX,g::rwX,o::rX,d:u::rwX,d:g::rwX,d:o::rX /home/apps

	# Allows users in the 'sudo' group to run commands as root without entering a password.
	# This is a convenience but should be used with caution and awareness of security implications.
	if ! test -f /etc/sudoers.d/nopasswd; then
		echo "%sudo ALL=(ALL:ALL) NOPASSWD:ALL" >/etc/sudoers.d/nopasswd
		chmod 440 /etc/sudoers.d/nopasswd # Restrictive permissions for sudoers files.
	fi

	# Configure the SSH server.
	# This section hardens the SSH server configuration.
	# It's applied if the custom port (822) isn't already in the config, implying it hasn't been configured by this script yet.
	if ! grep -q "Port 822" /etc/ssh/sshd_config; then
		put /etc/ssh/sshd_config <<-EOF
			# We omit ListenAddress so SSHD listens on all interfaces, both IPv4 and IPv6.

			# Supported HostKey algorithms by order of preference.
			# These are the private keys the server uses to identify itself to clients.
			# RSA and ED25519 are strong, modern algorithms.
			HostKey /etc/ssh/ssh_host_rsa_key
			HostKey /etc/ssh/ssh_host_ed25519_key

			# Select the host key algorithms that the server is willing to use for authentication.
			# Prioritizes modern, secure algorithms like Ed25519 and RSA with SHA2 signatures.
			# sk- variants are for FIDO/U2F hardware security keys.
			HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

			# Select the signature algorithms that the server is willing to use for certificate authority (CA) signatures.
			# Similar to HostKeyAlgorithms, prioritizing strong algorithms for CA-signed keys.
			CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

			# Select the key exchange algorithms that the server is willing to use for GSSAPI (Generic Security Services Application Program Interface) authentication.
			# GSSAPI is often used for Kerberos authentication. Modern curve-based algorithms are preferred.
			GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-

			# Select the public key algorithms that the server is willing to accept for user authentication.
			# Similar to HostKeyAlgorithms, ensuring clients use strong keys.
			PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

			# Choose stronger Key Exchange algorithms (KEX).
			# KEX algorithms are used to agree on a shared secret for the session.
			# Prioritizes modern, quantum-resistant (sntrup761x25519) and elliptic curve algorithms.
			KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

			# Use modern ciphers for encryption.
			# Ciphers are the algorithms used for encrypting the data stream.
			# ChaCha20-Poly1305 and AES-GCM are preferred for their security and performance.
			Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

			# Use MACs (Message Authentication Codes) with larger tag sizes.
			# MACs ensure data integrity. ETM (Encrypt-then-MAC) modes are generally preferred.
			MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

			# LogLevel VERBOSE logs user's key fingerprint on login. Needed to have a clear audit track of which key was using to log in.
			LogLevel VERBOSE

			# Don't let users set environment variables via SSH.
			# This can prevent some potential security risks.
			PermitUserEnvironment no

			# Forwarding to X11 is considered insecure as it can be exploited.
			X11Forwarding no

			# Disable various types of forwarding to reduce attack surface.
			AllowStreamLocalForwarding no # Disables forwarding of local Unix domain sockets.
			GatewayPorts no # Prevents remote hosts from connecting to forwarded ports.
			PermitTunnel no # Disables tun device forwarding.

			# Verify hostname matches IP.
			# Helps prevent DNS spoofing attacks, but can cause issues if DNS is not properly configured.
			UseDNS yes

			# TCPKeepAlive is not encrypted and can be spoofed. ClientAliveInterval is preferred.
			TCPKeepAlive no

			# Disable agent forwarding.
			# Agent forwarding can be risky if the server is compromised.
			AllowAgentForwarding no

			# Forbid root sessions.
			# Disallows direct root login via SSH, a common security best practice.
			PermitRootLogin no

			# Password are insecure.
			# Enforces key-based authentication, which is much more secure than passwords.
			PasswordAuthentication no

			# Allow users in 'remote' group to connect.
			# Restricts SSH access to users who are members of the 'remote' group.
			# To add and remove users from the group, respectively:
			# - usermod -aG remote <username>
			# - gpasswd -d <username> remote
			AllowGroups remote

			# Drop idle clients.
			# ClientAliveInterval: Sends a keep-alive message every 60 seconds.
			# ClientAliveCountMax: Disconnects after 30 unanswered keep-alive messages (30*60 = 30 minutes).
			ClientAliveInterval 60
			ClientAliveCountMax 30

			# Sets a timeout for authentication to complete.
			LoginGraceTime 10

			# Limits the number of authentication attempts per connection to 3.
			MaxAuthTries 3

			# Maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection.
			MaxSessions 2

			# Allow only one authentication at a time.
			# MaxStartups: Maximum number of concurrent unauthenticated connections.
			# The default is "10:30:100", this is more restrictive.
			MaxStartups 2

			# DebianBanner no: Disables display of the Debian-specific banner.
			# PrintMotd no: Disables display of the message of the day (MOTD).
			DebianBanner no
			PrintMotd no

			# Using a non-standard port (822 instead of 22) can help reduce exposure to automated attacks.
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
	# This ensures strong, fresh host keys are used.
	# -t rsa -b 4096: Generates a 4096-bit RSA key.
	# -t ed25519: Generates an Ed25519 key (modern, fast, and secure).
	# -N "": Sets an empty passphrase for the key.
	rm -f /etc/ssh/ssh_host_*
	ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
	ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

	# Applies the new SSH configuration and host keys.
	systemctl restart ssh

	# Allocate swap space equivalent to the available memory up to 16GB.
	# Swap space is used when the system runs out of physical RAM.
	if ! test -f /swapfile; then
		# Get available RAM in MB.
		ram=$(free -m | awk '/^Mem:/{print $2}')

		# Cap swap size at 16GB to avoid excessive storage usage.
		test "$ram" -lt 16384 || ram=16384
		
		# Try to use fallocate if available (much faster), otherwise use dd.
		if command -v fallocate >/dev/null 2>&1; then
			fallocate -l "${ram}M" /swapfile
		else
			dd if=/dev/zero of=/swapfile bs=1M count="$ram" status=progress
		fi
		
		# Set restrictive permissions on the swap file.
		chmod 600 /swapfile
		
		# Set up the swap file as a Linux swap area.
		mkswap /swapfile
		
		# Enable the swap file for immediate use.
		swapon /swapfile
		
		# Add an entry to /etc/fstab to make the swap file persistent across reboots.
		append /etc/fstab <<-EOF
			/swapfile none swap sw 0 0
		EOF
	fi

	# Reduce how likely the system is to swap memory.
	# Swappiness ranges from 0 (avoid swapping as much as possible) to 100 (will swap aggressively).
	# A value of 10 is a common recommendation for servers, prioritizing keeping applications in RAM.
	if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
		append /etc/sysctl.conf <<-EOF
			vm.swappiness = 10
		EOF

		# Apply sysctl changes without rebooting.
		sysctl -p 
	fi

	echo "Done."
}

register() {
	# Require privilege, i.e. sudo.
	# Checks if the effective user ID is 0 (root).
	test "$(id -u)" -eq 0 || fatal "This command must be ran as root."

	# Check if username is set.
	if test -z "$username"; then 
		fatal "Username is required."
	fi

	# Check if the user already exists.
	if id "$username" >/dev/null 2>&1; then 
		fatal "User '$username' already exists."
	fi

	# Check for required commands.
	# useradd: for creating new user accounts.
	# usermod: for modifying existing user accounts (e.g., adding to groups).
	dependencies="useradd usermod curl"
	for dep in $dependencies; do
		if ! command -v "$dep" >/dev/null 2>&1; then # Check if command exists.
			fatal "$dep could not be found, which is a hard dependency along with: $dependencies."
		fi
	done

	# Read public key from file or URL.
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

	# Create the new user.
	# -d /home/$username: sets the user's home directory.
	# -m: creates the home directory if it doesn't exist.
	# -s /bin/bash: sets the default login shell to bash.
	useradd -d "/home/$username" -m -s /bin/bash "$username"
	
	# Set a random password for the new user.
	# While SSH key authentication is enforced, a password is set for completeness and local console access.
	# tee /dev/tty: print out the credentials.
	echo "$username:$(random)" | tee /dev/tty | chpasswd

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

	echo "Done."
}

tools() {
	# Check if username is set.
	if test -z "$username"; then 
		fatal "Username is required."
	fi

	# Check if the user exists.
	if ! id "$username" >/dev/null 2>&1; then 
		fatal "User '$username' doesn't exist."
	fi

	# These tools are user-specific configurations and should be installed as the user.
	if test "$(id -u)" -eq 0; then
		# Duplicate the script somewhere the user can access it.
		provision="$(mktemp)"
		cp -p "$0" "$provision"
		su -l "$username" -c "sh $provision -- -t -u $username -l $log $debug"
		exit $?
	fi

	# Check for required software.
	# git: for cloning repositories.
	# curl: for fetching content from the web.
	dependencies="git curl"
	for dep in $dependencies; do
		if ! command -v "$dep" >/dev/null 2>&1; then
			fatal "$dep could not be found, which is a hard dependency along with: $dependencies."
		fi
	done

	if ! test -d "$HOME/.tmux"; then
		# Uses gpakosz/.tmux configuration: https://github.com/gpakosz/.tmux
		# This is a popular and comprehensive tmux configuration.
		# --depth=1: clones only the latest commit, making the clone faster and smaller.
		git clone --depth=1 https://github.com/gpakosz/.tmux.git "$HOME/.tmux"

		# Save a copy of the original .tmux.conf if it exists.
		save "$HOME/.tmux.conf"

		# Symlink the new .tmux.conf from the cloned repository to the home directory.
		# -s: create a symbolic link. -f: force (overwrite if exists).
		ln -s -f "$HOME/.tmux/.tmux.conf" "$HOME/.tmux.conf"

		# Copy the local configuration file for user-specific customizations.
		# Users should edit .tmux.conf.local, not .tmux.conf directly.
		cp "$HOME/.tmux/.tmux.conf.local" "$HOME/.tmux.conf.local"
	fi

	if ! test -d "$HOME/.vim_runtime"; then
		# Uses amix/vimrc configuration: https://github.com/amix/vimrc
		# This provides a well-regarded set of defaults, plugins, and configurations for Vim.
		git clone --depth=1 https://github.com/amix/vimrc.git "$HOME/.vim_runtime"

		# Run the installer script provided by the vimrc project for the basic configuration.
		sh "$HOME/.vim_runtime/install_basic_vimrc.sh"
	fi

	if ! test -d "$HOME/.zprezto"; then
		# Prezto: a configuration framework for Zsh: https://github.com/sorin-ionescu/prezto
		# Starship: a fast, customizable, cross-shell prompt: https://starship.rs/
		# Clone Prezto. --recursive is needed to get its submodules.
		git clone --recursive https://github.com/sorin-ionescu/prezto.git "$HOME/.zprezto"

		# Symlink Prezto's runcom files (zlogin, zlogout, zpreztorc, zprofile, zshenv, zshrc)
		# from the .zprezto directory to the home directory.
		# find ... -not -name README.md: excludes README files.
		find "$HOME/.zprezto/runcoms" -type f -not -name README.md | while read -r rcfile; do
			rcfile_name=".$(basename "$rcfile")"
			save "$HOME/$rcfile_name"
			ln -s -f "$rcfile" "$HOME/$rcfile_name"
		done

		# Change the current user's default shell to zsh.
		# `which zsh` finds the path to the zsh executable.
		# `id -nu` gets the current username.
		sudo chsh -s "$(which zsh)" "$(id -nu)"

		# Create the .config directory if it doesn't exist (standard location for user configs).
		mkdir -p "$HOME/.config"

		# Use a predefined starship preset (plain-text-symbols) for the prompt configuration.
		# This avoids issues with missing nerd fonts by default.
		starship preset plain-text-symbols >"$HOME/.config/starship.toml"

		# Enable syntax-highlighting and history-substring-search modules.
		sed "s/  'prompt'/  'syntax-highlighting' 'history-substring-search' 'prompt'/" "$HOME/.zpreztorc" | put "$HOME/.zpreztorc"
		
		# Comment out the default Prezto prompt theme to allow Starship to take over.
		# Prezto's prompt module would conflict with Starship if both are active.
		sed "s/\(zstyle ':prezto:module:prompt' theme\)/#\1/" "$HOME/.zpreztorc" | put "$HOME/.zpreztorc"
		
		# Add Starship initialization and custom aliases/settings to .zshrc.
		cat >>"$HOME/.zshrc" <<-EOF
			# Initialize Starship prompt for Zsh.
			# https://starship.rs/
			eval "\$(starship init zsh)"

			# CDPATH allows 'cd' to search in specified directories if the target isn't in the current path.
			# This makes it easier to navigate to /home/apps from anywhere.
			CDPATH="/home/apps"

			# Aliases for common commands.
			alias g=git
			alias d=docker
			alias c="docker compose"
		EOF
	fi

	echo "Done."
}

main() {
	# If $mode is 0, it means no command options were specified.
	if test $mode -eq 0; then
		fatal "No command option was specified: -i, -r or -t. See -h for help."
	fi
	
	# If bit 1 is set, the initialize command was requested.
	if test $((mode & 1)) -ne 0; then
		initialize
	fi

	# If bit 2 is set, the register command was requested.
	if test $((mode & 2)) -ne 0; then
		register
	fi

	# If bit 3 is set, the tools command was requested.
	if test $((mode & 4)) -ne 0; then
		tools
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
while getopts ":hxl:in:ru:k:t" option; do
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
		mode=$((mode | 1))
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
	t)
		mode=$((mode | 4))
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
