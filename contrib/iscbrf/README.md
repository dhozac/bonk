# iscBrf
This script generates ISC dhcpd and bind compatible files from bonk data. It might be useful if you want bind and/or dhcpd to reflect changes made in bonk.

## Usage
Some modifications to templates and/or scripts required, depending on your requirements. Create configuration file(s) for your needs, the server option should point to the bonk endpoint, usually something like https://your.server.example/bonk, run iscbrf.py like:

```# ./iscbrf.py /etc/iscbrf/internal.ini```

Output paths should get populated with dhcp/bind files

### Configuration file example
Available in EXAMPLE.internal.ini, type can be whatever type you have under bonk/zone/ normally internal or external.
