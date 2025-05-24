# Provision

> For the journey ahead.

## Warning

This script will:

- Change configurations that might lock you out, break stuff or otherwise compromise the security or stability of your server.
- Output secrets in plain text and save them to the disk.

⚠️ You MUST read it whole and understand exactly what it does before proceeding.

## About

Provision is a POSIX-compliant shell script that helps withe the initial configuration required for a production grade Debian-based server to host web sites and applications. It's tailor made for my needs but it just might suit yours.

Here's an overview of what it can do;

- Update the server's hostname.
- Upgrade existing packages.
- Install Docker, fail2ban, and a few other packages.
- Harden SSH configuration and switch to an alternative port (822).
- Configure firewall to block any incoming traffic except on selected ports (822, 443, 80).
- Change root's password.
- Create a deployment user.
- Allow passwordless sudo.
- Create swap space equivalent to the available memory up to 16GB.
- Register new system administrator user.
- Install opinionated administrative tools.

Some options are available via command flags. See -h.

## References

- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
- https://infosec.mozilla.org

## License

This project is licensed under [public domain](LICENSE).
