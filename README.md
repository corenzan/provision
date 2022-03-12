# Provision

> For the journey ahead.

## Warning

This script will:

- Change configurations that might lock you out, break stuff or otherwise compromise your server.
- Output secrets in plain text and save it to the disk.

⚠️ You MUST read it whole and understand exactly what it does before proceeding.

## About

Provision is a shell script in POSIX Bash to set the initial configuration required for a production grade server to host web sites and applications using Dokku. It's tailor made for my needs but it just might suit yours.

Here's an overview of what it'll do.

- Update the server's hostname.
- Change root's password.
- Create new user and setup remote authentication.
- Allow passwordless sudo.
- Reconfigure SSH and switch to an alternative port (822).
- Disable IPv6 due to DigitalOcean's issue with Docker.
- Reset firewall configuration.
- Upgrade existing packages.
- Install new software such as Docker and fail2ban.
- Block all incoming traffic except on selected ports.
- Create swap space equivalent to the available memory.

Some options are available via command flags. See --help.

## Usage example

```
$ ./provision.sh -u arthur -n gero.corenzan.com -k https://gist.githubusercontent.com/haggen/e9f9ef40da12f209ee630be5d7ba3805/raw/06adcfb30c6b434adafbc698b78d9d1a083144c2/id_rsa.pub 
```

## References

- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server

## License

This project is licensed under [public domain](LICENSE).
