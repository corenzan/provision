# Provision

> Bootstrap server setup.

## Warning

This script will require elevated privilege (a.k.a. `sudo`) and will touch the security of your server. You must read it and understand what it does before proceeding. You are fully responsible for anything that may happen to your servers. Please note that it's only been tested on stock installations of Ubuntu 14 (trusty), 16 (xenial), and 17 (zesty).

## About

Provision is a bash script I wrote to bootstrap the setup of new servers on cloud providers such as AWS, Digital Ocean, and Linode. It's tailor made for my needs but it just might suit you.

### What it'll do:

- Reset root's password.
- Create a new administrator user and setup SSH in an alternative port (822).
- Upgrade all installed packages and install third-party software.
- Block all incoming traffic except on ports 822 (for SSH), 80, and 443.
- Setup swap space with half the available memory.

Currently it doesn't provide options or prompts during execution, so **you must edit the script to suit your needs beforehand**.

## License

This project is licensed under [public domain](LICENSE).

## Contribution

Please if you think you found a bug, if you have concerns or suggestions, do send them my way by opening a new issue or requesting a pull request. All help is welcome.
