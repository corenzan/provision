# Provision

> Feed your servers.

## Warning

This script will require elevated privilege, i.e. `sudo`, and it'll change configurations that might lock you out or leave your servers exposed. You MUST read it whole and understand exactly what it does before proceeding.

## About

Provision is a script in POSIX Bash to automate the setup of new servers on cloud providers such as AWS, DigitalOcean, and Linode. It's tailor made for my needs but it just might suit you.

Here's an overview of what it'll do.

- Reset root password.
- Allow passwordless sudo.
- Reconfigure SSH and switch to an alternate port (822).
- Disable IPv6 due to DigitalOcean's issue with Docker.
- Upgrade existing packages.
- Install new packages such as Docker and fail2ban.
- Reset firewall configuration.
- Block all incoming traffic except on selected ports.
- Create swap space equivalent to the available memory.
- Output secrets in plain text and save it to the disk.

Some options are available via command flags. Try running with --help.

## Reference

- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server

## License

This project is licensed under [public domain](LICENSE).
