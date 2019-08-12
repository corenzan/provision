# Provision

> Bootstrap server setup.

## Warning

This script will require elevated privilege, i.e. `sudo`, and will meddle with the security of your operating system. You MUST read it whole and understand exactly what it does before proceeding. You are fully responsible for anything that may come to happen to your server.

## About

Provision is a script in Bash to bootstrap the setup of new servers on cloud providers such as AWS, DigitalOcean, and Linode. It's tailor made for my needs but it just might suit you.

Here's an overview of what it'll do.

- Reset root password.
- Create a new user and authorize your public key.
- Reset SSH configuration and use an alternative port (822).
- Disable IPv6.
- Upgrade existing packages and install new software.
- Reset firewall configuration.
- Block all incoming traffic except on ports 822 (for SSH), 80, and 443.
- Configure automatic unattended upgrades for security patches.
- Setup swap space the same size as available memory.
- Output secrets in plain text and save to the disk.

Currently it'll only prompt for username and public key. For everything else you'll have to edit the script beforehand.

## Reference

- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server

## License

This project is licensed under [public domain](LICENSE).
