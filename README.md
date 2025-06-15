# Provision

> For the journey ahead.

## Warning

This script will:

- Change configurations that might break stuff, lock you out of access, or otherwise compromise the security or stability of your server.
- Output secrets in plain text and save them to disk.

⚠️ You MUST read it in full and understand exactly what it does before proceeding.

## About

Provision is a POSIX-compliant shell script that helps with the initial configuration required for a production-grade Debian-based server to host websites and applications. It's tailor-made for my needs, but it just might suit yours.

Here's an overview of what it'll do:

- Update the server's hostname.
- Upgrade existing packages.
- Install Docker, fail2ban, and several other software.
- Harden SSH configuration and switch to an alternative port (822).
- Configure the firewall to block any incoming traffic except on selected ports (822, 443, 80) on both IPv4 and IPv6.
- Change the root password.
- Create a dedicated user and directory for project deployment, with proper ACL and permissions so other users can manage it.
- Allow passwordless sudo.
- Create swap space equivalent to the available memory, up to 16GB.
- Register a new system administrator user with a strong random password and SSH access.
- Install opinionated administrative tools.

Some options are available via command flags. See `-h`.

## License

This project is licensed under [public domain](LICENSE).
