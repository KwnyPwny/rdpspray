# rdpspray
```
usage: rdp_sprayer.py [-h] [-D DOMAIN] (-i IP_FILE | -I IPS [IPS ...])
                      (-u USER_FILE | -U USERS [USERS ...]) -P PASSWORD
                      [-o OUTPUT_FILE]
```

Requires freerdp2-x11. This script searches for valid RDP credentials in a
network via password spraying. It requires IPs, users and the password. If the
scanned hosts are part of a domain, the domain name is required as well. Try
to obtain valid credentials with the metasploit module smb_login or
crackmapexec, prior using this script.

optional arguments:
* `-h, --help`            show this help message and exit
* `-D DOMAIN, --domain DOMAIN`
                        Domain
* `-i IP_FILE, --ip_file IP_FILE`
                        IP file
* `-I IPS [IPS ...], --ips IPS [IPS ...]`
                        IPs
* `-u USER_FILE, --user-file USER_FILE`
                        User file
* `-U USERS [USERS ...], --users USERS [USERS ...]`
                        users
* `-P PASSWORD, --password PASSWORD`
                        Password
* `-o OUTPUT_FILE, --output-file OUTPUT_FILE`
                        Output file
