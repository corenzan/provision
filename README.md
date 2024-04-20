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

Assuming you're root and you've downloaded the script to your server.

```sh
./provision.sh --username bob --hostname example.com --public-key https://example.com/id_rsa.pub --dokku --digital-ocean
```

## References

- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server

## License

This project is licensed under [public domain](LICENSE).
