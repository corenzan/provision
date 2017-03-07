# Provision

> Script to setup a new server.

## Warning

This script will require elevated privilege (a.k.a. `sudo`) and will touch the security of your server. You should read it and understand it before using it. You are fully responsible if anything bad happens to your servers. I don't provide support. Also it has only been tested on stock installations of Ubuntu 14 (trusty) and 16 (xenial).

## About

Privision is simply a bash script I made to bootstrap new servers I create on cloud providers (AWS, Digital Ocean, Linode, etc).

### What it'll do:

- Configure shell encoding to use UTF-8.
- Update and upgrade installed packages.
- Reset root's password.
- Create a new administrator user.
- Setup New Relic server monitoring and Docker CE.
- Configure SSH to use RSA authentication only and custom port (822).
- Reset iptables with a minimum set of rules to server HTTP and HTTPS and block everything else.

Currently it doesn't provide any options during execution, **you must edit the script to suit your needs beforehand**.

## Acknowledgement

I wrote the script based on articles, posts and snippets around the internet talking about best practices and minimum configuration for web servers. I wish I had saved all the links, but I don't so I just want to thank all the people that freely shared your knowledge with the internet.

## License

This project is licensed under [public domain](LICENSE).

## Contribution

Please if you think you found a bug, if you have concerns or suggestions, do send them my way by opening a new issue or even sending a pull request. Any help is much appreciated.
