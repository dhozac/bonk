# The bonk data model

## Fundamentals

For the IP addressing parts of bonk, it uses three different types of
objects, structured in a hierarchy. The top-level object is called a
block. A block is a logical grouping of physical networks, to define
permissions and where it is terminated in the network. Blocks can
themselves contain other blocks. A prefix is a representation of a
physical network, one where devices can connect and use their
assigned addresses. An address is the lowest level, representing a
single IP address assigned to an interface on a device, complete with
a hostname and (maybe) MAC addresses.

In addition to the IP addressing parts, it also has knowledge of the
DNS zones that are available, as well as any records that belong in
them.

## VRFs

VRFs are defined by an integer. They serve little purpose other than
to distinguish separate networks from eachother, to allow for things
like overlapping IP space.

### Fields

- vrf
  * The numeric identifier for the VRF.
- name
  * The name of the VRF.

## Blocks

A block is identified by three fields, the VRF identifier (an
integer), a network address (a string, e.g. 10.0.0.0), and the
network length (an integer, e.g. 16).

A block can have permissions set to allow users three levels of
access. The permissions granted will grant access to all blocks,
prefixes, and addresses within this block. 

### Fields

- vrf
  * The numeric identifier for the VRF.
- network
  * The network address for this block.
- length
  * The network length for this block.
- announced_by
  * A reference to the device that is responsible for this block.
    This is the device where new prefixes allocated out of this block
    should be configured.
- permissions
  - read
    * A list of groups that should be granted read access to this
      block.
  - create
    * A list of groups that should be granted access to create new
      prefixes from this block.
  - write
    * A list of groups that should have full access to this block.

## Prefixes

A prefix is identified by three fields, the VRF identifier (an
integer), a network address (a string, e.g. 10.0.0.0), and the
network length (an integer, e.g. 24).

From a prefix, users with create or write permissions can allocate
addresses for their devices.

### Fields

- vrf
  * The numeric identifier for the VRF.
- network
  * The network address for this prefix.
- length
  * The network length for this prefix.
- asn
  * The ASN this prefix belongs to.
- name
  * The name of this prefix. Must be unique.
- state
  * The state of this prefix. Must be one of allocated, reserved, or
    quarantine.
    reserved is for prefixes that are not yet in use, but that
    might be used in the future for a designated purpose.
    qurantine is for prefixes that might have been used in the past,
    and where old references to it might still exist so should be
    avoided for new things.
- permissions
  - read
    * A list of groups that should be granted read access to this
      prefix.
  - create
    * A list of groups that should be granted access to create new
      addresses from this prefix.
  - write
    * A list of groups that should have full access to this prefix.
- gateway
  * The address to the gateway to the rest of the network for this
    prefix.
- dhcp
  - enabled
    * Boolean designating whether DHCP is enabled on this network or
      not.
  - server_set
    * String referring to the DHCP server set where this prefix
      should be configured.
  - range
    * A list of exactly two addresses, the first being the start of
      the DHCP range, and the second being the end.
  - options
    * A list of free-form lines to configure DHCP further.
- ddns
  - zone
    * Name of the zone to register DDNS in.
  - name
    * Name of the DDNS key.
  - algorithm
    * Algorithm to use for signing DDNS requests.
  - key
    * Key to use for signing DDNS requests.
  - server
    * Where to send the DDNS requests.

## Addresses

An address is identified by two fields, the VRF identifier (an
integer), and an IP address (a string, e.g. 10.0.0.1). The hostname
that is defined for the address also has to be unique. This means
that a device with multiple addresses will need multiple hostnames.

### Fields

- vrf
  * The numeric identifier for the VRF.
- ip
  * The IP address.
- name
  * The hostname for this address. The domain must be registered as a
    DNS zone, where the user creating the entry must also have create
    or write permissions.
- state
  * The state of this address. Must be one of allocated, reserved, or
    quarantine.
    reserved is for addresses that are not yet in use, but that
    might be used in the future for a designated purpose.
    qurantine is for addresses that might have been used in the past,
    and where old references to it might still exist so should be
    avoided for new things.
- dhcp_mac
  * List of MAC addresses in de:ad:be:ef:f0:0d format that the
    device will use to request a static DHCP lease for this address.
- ttl
  * Optional field to override the default time-to-live for this
    address.
- permissions
  - read
    * A list of groups that should be granted read access to this
      address.
  - write
    * A list of groups that should have full access to this address.

## DNS zones

A DNS zone is identified by its name, and its classification.
Currently two classifications exist, internal and external. Users can
create records and addresses in a zone if they have create or write
permissions on the zone.

### Fields

- type
  * Classification of the zone as either internal or external.
- name
  * Fully qualified name of the zone, without a trailing period.
- soa
  - authns
    * Authoritative nameserver for this zone. Without trailing period.
  - email
    * Email address to use for this zone. Without trailing period.
  - refresh
    * Refresh internal in number of seconds.
  - retry
    * Retry interval in number of seconds.
  - expiry
    * Expiry interval in number of seconds.
  - nxdomain
    * NXDOMAIN cache timeout in number of seconds.
- ttl
  * Default time-to-live for this zone in seconds.
- options
  - ddns
    - name
      * Name of the key to use for verifying DDNS requests.
    - algorithm
      * Algorithm to use for verifiying DDNS requests.
    - key
      * Key to use for verifying DDNS requests.
  - forwarders
    * If set, turns this zone into a forwarded zone, and contains a
      list of IP addresses to forward the zone to.
  - notify
    * If set, a list of IP addresses to send notifies to when this
      zone is updated.
  - masters
    * If set, turns this zone into a slave zone, and contains a list
      of IP addresses to use as masters.
- needs_review
  * Boolean determining whether reviews are required for changes to
    this zone.
- permissions
  - read
    * A list of groups that should be granted read access to this
      zone.
  - create
    * A list of groups that should be granted access to create new
      records and addresses in this zone.
  - write
    * A list of groups that should have full access to this zone.

## DNS records

A DNS record is identified by its name, and its type. A record is
contained within a zone, which is specified in the record. This is to
enable glue records.

The value of a record is a list. A round-robin A record would thusly
be a single record, with its multiple values in the list.

### Fields

- name
  * The name of this record.
- type
  * The type of record, one of: A, AAAA, CNAME, MX, NS, PTR, SRV, TXT, CAA
- zone
  * The zone that this record is in.
- ttl
  * Optional field to override the default time-to-live for this
    record.
- value
  * A list of values for this record. Note that in the cases of
    records with values of other names, e.g. CNAME, MX, NS, PTR, the
    trailing dot must be included if a fully-qualified name is used.
- permissions
  - read
    * A list of groups that should be granted read access to this
      record.
  - write
    * A list of groups that should have full access to this record.
