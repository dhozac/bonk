# How to use bonk

This document contains a number of more-or-less common use-cases and
how to achieve them with bonk.

For a reference of the data model, look at
[the data model](DATAMODEL.md).

## IPAM

### Create a new block

To create a new block, send a `POST` to `/bonk/block/` containing the
data for the block. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/block/ <<EOF
{
  "log": "Add the new testing firewall's block",
  "vrf": 0,
  "network": "10.1.0.0",
  "length": 16,
  "announced_by": "socrates://server/firewall-lldp",
  "permissions": {
    "create": ["everyone"]
  }
}
EOF
```

This block will let users in the group everyone create new networks
in the block of 10.1.0.0/16, which will then be provisioned onto the
firewall with an LLDP domain of firewall-lldp through Socrates.

### Update a block

To change or add a field to a block, simply issue a `PATCH` request
to `/bonk/block/<vrf>/<network>/<length>/`

For example, to change which groups get to use the block above to
group1 and group2, the request would look like:
```
curl -u $USER -XPATCH -H 'Content-Type: application/json' --data @- \
    https://server/bonk/block/0/10.1.0.0/16 <<EOF
{
  "log": "everyone can't handle this",
  "permissions": {
    "create": ["group1", "group2"]
  }
}
EOF
```

To remove a field, you will need to issue a `PUT` request containing
all of the fields you want to keep. For example, to remove the
`announced_by` and `permissions` from our block, the request would
look like:
```
curl -u $USER -XPUT -H 'Content-Type: application/json' --data @- \
    https://server/bonk/block/0/10.1.0.0/16 <<EOF
{
  "log": "Let's divide this up further",
  "vrf": 0,
  "network": "10.1.0.0",
  "length": 16,
}
EOF
```

### Delete a block

To delete a block, simply issue a `DELETE` request to it. For example:
```
curl -u $USER -XDELETE -H 'Content-Type: application/json' \
    https://server/bonk/block/0/10.1.0.0/16
```

### Listing prefixes

You can list all prefixes that you have permissions to see by
issuing a `GET` to `/bonk/prefix/`.

### Allocate a prefix

Allocating a prefix out of a block is the process of finding a free
network that meets the requested size in the block, and creating a
new prefix with the result. The result from this request is the
newly allocated prefix.

To allocate a prefix with enough IP addresses for 10 servers, issue
a `POST` to `/bonk/block/<vrf>/<network>/<length>/` like the
following:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/block/0/10.1.0.0/16/allocate <<EOF
{
  "hosts": 10,
  "name": "my-network",
  "permissions": {
    "write": ["group1"]
  }
}
EOF
```

The allocate request accepts all of the fields of a prefix, but
requires only `name`, `permissions`, and `hosts` (or `length` if you
prefer specifying your prefix length).

#### Allocate a prefix with DHCP

One of those fields would be to enable DHCP on the prefix. Such a
request would look something like:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/block/0/10.1.0.0/16/allocate <<EOF
{
  "hosts": 10,
  "name": "my-network-dhcp",
  "permissions": {
    "write": ["group1"]
  },
  "dhcp": {
    "enabled": true,
    "server_set": "site1"
  }
}
EOF
```

### Create a prefix

If you know what you want and you don't need no stinking computer
telling you what prefix to use, you can `POST` the complete prefix
to `/bonk/prefix/`. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/prefix/ <<EOF
{
  "log": "I rule",
  "vrf": 0,
  "network": "10.1.255.0",
  "length": 24,
  "name": "my-network-i-know-whats-best",
  "state": "allocated",
  "gateway": "10.1.255.128",
  "permissions": {
    "write": ["group1"]
  },
  "dhcp": {
    "enabled": true,
    "server_set": "site1"
  }
}
EOF
```

### Update a prefix

If you would like to add another group with access to your prefix,
you can do so by sending a `PATCH` to
`/bonk/prefix/<vrf>/<network>/<length>`. For example:
```
curl -u $USER -XPATCH -H 'Content-Type: application/json' --data @- \
    https://server/bonk/prefix/0/10.1.255.0/24 <<EOF
{
  "log": "Give group2 permissions to create addresses",
  "permissions": {
    "create": ["group2"]
  }
}
EOF
```

### Delete a prefix

To delete a prefix, simply issue a `DELETE` request to it. For
example:
```
curl -u $USER -XDELETE -H 'Content-Type: application/json' \
    https://server/bonk/prefix/0/10.1.255.0/24
```

### Listing addresses

You can list all addresses that you have permissions to see by
issuing a `GET` to `/bonk/address/`.

### Allocate an address

Allocating an address picks the first free address from the prefix,
and assigns a hostname and possibly MAC addresses to it.

To allocate an address, send a `POST` to the prefix on
`/bonk/prefix/<vrf>/<network>/<length>/allocate/`. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/prefix/0/10.1.0.32/28/allocate <<EOF
{
  "name": "my-server.bonk.internal"
}
EOF
```

### Create an address

If you know which address you want, you can just send a `POST` to
`/bonk/address/` directly with the complete address record. For
example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/address/ <<EOF
{
  "log": "What is the meaning of this?",
  "state": "allocated",
  "vrf": 0,
  "ip": "10.1.0.42",
  "name": "my-meaningful-server.bonk.internal"
}
EOF
```

### Update an address

If you want to change the name of your server, you will need to issue
a `PATCH` to the address to update it. For example:
```
curl -u $USER -XPATCH -H 'Content-Type: application/json' --data @- \
    https://server/bonk/address/0/10.1.0.42 <<EOF
{
  "log": "I like this better",
  "name": "my-purposeful-server.bonk.internal"
}
EOF
```

### Delete an address

To delete an address, simply issue a `DELETE` request to it. For
example:
```
curl -u $USER -XDELETE -H 'Content-Type: application/json' \
    https://server/bonk/address/0/10.1.0.42
```

## DNS

### Listing zones

You can list all zones that you have permissions to see by issuing a
`GET` to `/bonk/zone/`.

### Create a master zone

A master zone is a zone whose contents will be managed by bonk. If
you want to allocate addresses and put records into it through bonk,
this is what you want. It is also the default.

To create one, issue a `POST` to `/bonk/zone/`. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/zone/ <<EOF
{
  "log": "Add the internal main zone",
  "type": "internal",
  "name": "bonk.internal",
  "soa": {
    "authns": "dns.bonk.internal",
    "email": "hostmaster.bonk.internal",
    "refresh": 86400,
    "retry": 7200,
    "expiry": 3600000,
    "nxdomain": 172800
  },
  "permissions": {
    "write": ["group1"]
  }
}
EOF
```

### Create a DDNS zone

A DDNS zone is a zone managed somewhere else, through the use of a
DDNS key and requests made to the DNS master.

To create one, issue a `POST` to `/bonk/zone/`. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/zone/ <<EOF
{
  "log": "Add DDNS zone",
  "type": "internal",
  "name": "ddns.bonk.internal",
  "permissions": {
    "write": ["group1"]
  },
  "options": {
    "ddns": {
      "name": "DDNS_KEY",
      "algorithm": "HMAC-MD5",
      "key": "deadbeef"
    }
  }
}
EOF
```

### Create a forwarded zone

A forwarded zone is one that isn't stored on the bonk-managed DNS
servers at all. All requests to these zones are instead sent to
another set of DNS servers, for instance AD.

To create one, issue a `POST` to `/bonk/zone/`. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/zone/ <<EOF
{
  "log": "Add forwarded zone",
  "type": "internal",
  "name": "ad.bonk.internal",
  "permissions": {
    "write": ["group2"]
  },
  "options": {
    "forwarders": ["10.1.1.10", "10.1.2.10"]
  }
}
EOF
```

### Create a slave zone

A slave zone is a zone that is transferred from another set of DNS
servers, and then served from that copy.

To create one, issue a `POST` to `/bonk/zone/`. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/zone/ <<EOF
{
  "log": "Add slave zone",
  "type": "internal",
  "name": "slave.bonk.internal",
  "permissions": {
    "write": ["group3"]
  },
  "options": {
    "masters": ["10.1.3.10", "10.144.10"]
  }
}
EOF
```

### Update a zone

If your DDNS zone key is compromised, you will have to update your
zone with the new key. To do that, issue a `PATCH` to
`/bonk/zone/<name>`. For example:
```
curl -u $USER -XPATCH -H 'Content-Type: application/json' --data @- \
    https://server/bonk/zone/ddns.bonk.internal <<EOF
{
  "log": "Posted DDNS key in a HOWTO. Oops",
  "options": {
    "ddns": {
      "key": "deadeebeefee"
    }
  }
}
EOF
```

### Delete a zone

To delete a zone, simply issue a `DELETE` request to it. For
example:
```
curl -u $USER -XDELETE -H 'Content-Type: application/json' \
    https://server/bonk/zone/slave.bonk.internal
```

### Listing records

You can list all records that you have permissions to see by issuing
a `GET` to `/bonk/record/`.

### Create a record

You can create any kind of record by issuing a `POST` to
`/bonk/record/`. The combination of name and type has to be unique.
The exception is if you want to create a `CNAME`, in which case that
has to be only record for that name.

For any record types where you're pointing to another hostname, e.g.
`CNAME`, `MX`, `NS`, ensure that you include the trailing dot at the
end of the name. Otherwise the name of the zone will be appended.

#### Creating a round-robin `A` record

A round-robin `A` record is a name that resolves to a list of IP
addresses. In a lot of software, this can be used for very simple
load balancing and/or high availability. This is how you create one:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/record/ <<EOF
{
  "log": "Add round-robin record for bonk",
  "name": "server.bonk.internal",
  "zone": "bonk.internal",
  "type": "A",
  "value": [
    "10.1.0.42",
    "10.1.0.43",
    "10.1.0.44"
  ]
}
EOF
```

#### Creating a `CNAME` record

A `CNAME` is an alias from one domain name to another. This can be
used to point your service name (e.g. `server`) to your server, if
you're only every going to have one. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/record/ <<EOF
{
  "log": "Add alias for bonk",
  "name": "server.bonk.internal",
  "zone": "bonk.internal",
  "type": "CNAME",
  "value": ["server-prod1.bonk.internal."]
}
EOF
```

Note that while value is still a list, for a `CNAME`, the list may
only contain one entry. Also note the trailing dot in the value.

#### Creating an `NS` record

`NS` records are used to delegate a part of the domain tree to
another set of nameservers. For example:
```
curl -u $USER -XPOST -H 'Content-Type: application/json' --data @- \
    https://server/bonk/record/ <<EOF
{
  "log": "Delegate part of the internal namespace to AWS",
  "name": "eu-west-1.bonk.internal",
  "zone": "bonk.internal",
  "type": "NS",
  "value": [
    "ns-1.awsdns-01.org.",
    "ns-2.awsdns-02.net.",
    "ns-3.awsdns-03.com.",
    "ns-4.awsdns-04.co.uk."
  ]
}
EOF
```

Again, note the trailing dots in the value.

### Update a record

If you would like to update a record, issue a `PATCH` to it on
`/bonk/record/<name>/<type>/`. For example, to update the name of the
single server running bonk:
```
curl -u $USER -XPATCH -H 'Content-Type: application/json' --data @- \
    https://server/bonk/record/server.bonk.internal/CNAME/ <<EOF
{
  "log": "Replace with a much better server!",
  "value": ["server-prod2.bonk.internal."]
}
EOF
```

### Delete a record

To delete a record, simply issue a `DELETE` request to it. For
example:
```
curl -u $USER -XDELETE -H 'Content-Type: application/json' \
    https://server/bonk/record/server.bonk.internal/CNAME
```
