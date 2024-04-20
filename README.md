# Provision

> For the journey ahead.

## Warning

This script will:

- Change configurations that might lock you out, break stuff or otherwise compromise your server.
- Output secrets in plain text and save it to the disk.

⚠️ You MUST read it whole and understand exactly what it does before proceeding.

## About

Provision is a shell script in Bash that sets the initial configuration required for a production grade server to host web sites and applications. It's tailor made for my needs but it just might suit yours.

Here's an overview of what it'll do.

- Update the server's hostname.
- Upgrade existing packages.
- Install Docker, fail2ban, and a few more new packages.
- Harden SSH configuration and switch to an alternative port (822).
- Reset firewall configuration and block all incoming traffic except on selected ports (822, 443, 80, and 53).
- Change root's password.
- Create new user, setup remote authentication, and customize its shell.
- Allow passwordless sudo.
- Create swap space equivalent to the available memory.

Some options are available via command flags. See --help.

## Usage example

Assuming you're root:

```sh
cd /tmp
curl -O provision.sh https://raw.githubusercontent.com/corenzan/provision/master/provision.sh
chmod +x provision.sh
./provision.sh --username arthur --hostname krusty.corenzan.com --public-key https://gist.githubusercontent.com/haggen/e9f9ef40da12f209ee630be5d7ba3805/raw/06adcfb30c6b434adafbc698b78d9d1a083144c2/id_rsa.pub --dokku --digital-ocean
```

## References

- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
- https://infosec.mozilla.org

## License

This project is licensed under [public domain](LICENSE).
