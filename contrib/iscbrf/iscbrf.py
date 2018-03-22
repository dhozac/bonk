#!/usr/bin/python -tt

# Copyright 2017 Klarna AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import jinja2
import logging
import os
import sys
import requests
import dns.reversename
import netaddr
import json
import dns.zone
import dns.rdatatype
import ConfigParser

class iscBonk(object):

    def __init__(self, config):
        template_dir = "templates/"
        if config.has_option("iscbrf", "template_dir"):
            template_dir = config.get("iscbrf", "template_dir")
        self.named_template = template_dir + 'named.conf.j2'
        self.named_slave_template = template_dir + 'named-slave.conf.j2'
        self.dhcpd_template = template_dir + 'dhcpd.conf.j2'
        self.zone_template = template_dir + 'zone.j2'
        self.cache_path = '/var/cache/bind/'
        if config.has_option("iscbrf", "cache_path"):
            self.cache_path = config.get("iscbrf", "cache_path")
        self.zone_path = '/etc/named/pri/'
        if config.has_option("iscbrf", "zone_path"):
            self.zone_path = config.get("iscbrf", "zone_path")
        self.zone_output_path = '/etc/named/pri/'
        if config.has_option("iscbrf", "zone_output_path"):
            self.zone_output_path = config.get("iscbrf", "zone_output_path")
        self.default_soa = {
            'authns': config.get("default_soa", "authns"),
            'email': config.get("default_soa", "email"),
            'refresh': config.getint("default_soa", "refresh"),
            'retry': config.getint("default_soa", "retry"),
            'expiry': config.getint("default_soa", "expiry"),
            'nxdomain': config.getint("default_soa", "nxdomain"),
        }
        self.default_ns = [config.get("default_ns", option) for option in config.options("default_ns")]
        if config.has_section("slave_masters"):
            self.slave_masters = [config.get("slave_masters", option) for option in config.options("slave_masters")]
        else:
            self.slave_masters = []
        self.log = logging.getLogger(__name__)

    def buildDhcpdConfig(self, prefixes, addresses, outfile=None):
        r = None
        j2 = jinja2.Environment(
            loader=jinja2.FileSystemLoader(
                os.path.dirname(os.path.abspath(self.dhcpd_template))
            ),
            trim_blocks=True,
            lstrip_blocks=True)
        j2.filters['netmask'] = lambda x: netaddr.IPNetwork("127.0.0.0/%d" % x).netmask

        r = j2.get_template(os.path.basename(self.dhcpd_template)).render(prefixes=sorted(prefixes, key=lambda x: x['network']), addresses=sorted(addresses, key=lambda x: x['ip']))

        if outfile:
            self.log.info('writing dhcpd config to {0}'.format(outfile))
            with open(outfile, 'w') as f:
                f.write(r)

        return r

    def buildBindConfig(self, zones, master_outfile=None, slave_outfile=None):
        r = None

        for zone in zones.values():
            self.makeZoneFile(zone, os.path.join(self.zone_output_path, zone['name']))

        j2 = jinja2.Environment(
            loader=jinja2.FileSystemLoader(
                os.path.dirname(os.path.abspath(self.named_template))
            ),
            trim_blocks=True,
            lstrip_blocks=True)

        r_master = j2.get_template(os.path.basename(self.named_template)).render(zones=sorted(zones.values(), key=lambda x: x['name']), zone_path=self.zone_path)

        r_slave = j2.get_template(os.path.basename(self.named_slave_template)).render(zones=sorted(zones.values(), key=lambda x: x['name']), slave_masters=self.slave_masters)

        if master_outfile and r_master:
            self.log.info('writing bind config {0}'.format(master_outfile))
            with open(master_outfile, 'w') as f:
                f.write(r_master)

        if slave_outfile and r_slave:
            self.log.info('writing bind slave config {0}'.format(slave_outfile))
            with open(slave_outfile, 'w') as f:
                f.write(r_slave)

        return r_master

    def makeZoneFile(self, zone, outfile=None):
        r = None
        # sort the record list by record name if it exists
        for record in zone['records']:
            if record['name'] == zone['name'] and record['type'] == 'NS':
                break
        else:
            zone['records'].append({'name': zone['name'], 'type': 'NS', 'value': self.default_ns})
        zone['records'] = sorted(zone['records'], key=lambda k: k['name'])
        if 'soa' not in zone:
            zone['soa'] = self.default_soa
        if outfile and os.path.exists(outfile):
            zf = dns.zone.from_file(outfile, origin=zone['name'])
            serial = zf.find_rrset(zone['name'] + '.', dns.rdatatype.SOA).items[0].serial
        else:
            serial = 1

        j2 = jinja2.Environment(
            loader=jinja2.FileSystemLoader(
                os.path.dirname(os.path.abspath(self.zone_template))
            ),
            trim_blocks=True,
            lstrip_blocks=True)

        r = j2.get_template(os.path.basename(self.zone_template)).render(zone=zone, serial=serial + 1)

        if outfile and r:
            if os.path.exists(outfile):
                with open(outfile, 'r') as f:
                    contents = f.read()
                changed = len(set(r.splitlines()).symmetric_difference(set(contents.splitlines()))) > 2
            else:
                changed = True
            if changed:
                self.log.info('writing zone file to {0}'.format(outfile))
                with open(outfile, 'w') as f:
                    f.write(r)
            else:
                self.log.debug('not writing zone file to {0}'.format(outfile))

        return r

if __name__ == "__main__":
    config = ConfigParser.SafeConfigParser()
    config.read(sys.argv[1:])
    server = ""
    if config.has_option("api", "uri"):
        server = config.get("api", "uri")
    username = config.get("api", "username")
    password = config.get("api", "password")
    auth = (username, password)
    my_type = config.get("iscbrf", "type")

    response = requests.get(server + "zone/", params={'type': my_type}, auth=auth)
    if response.status_code != 200:
        print >> sys.stderr, "Failed to get my zones: %r" % response.content
        sys.exit(1)
    zones = dict([(zone['name'], zone) for zone in response.json()])

    response = requests.get(server + "zone/", auth=auth)
    if response.status_code != 200:
        print >> sys.stderr, "Failed to get all zones: %r" % response.content
        sys.exit(1)
    not_my_zones = set([zone['name'] for zone in response.json() if zone['name'] not in zones])

    response = requests.get(server + "prefix/", auth=auth)
    if response.status_code != 200:
        print >> sys.stderr, "Failed to get prefixes: %r" % response.content
        sys.exit(1)
    prefixes = response.json()

    response = requests.get(server + "address/", params={'state': 'allocated'}, auth=auth)
    if response.status_code != 200:
        print >> sys.stderr, "Failed to get addresses: %r" % response.content
        sys.exit(1)
    addresses = response.json()

    for zone in zones.values():
        response = requests.get(server + "record/", params={'zone': zone['name']}, auth=auth)
        if response.status_code != 200:
            print >> sys.stderr, "Failed to get DNS records for %s: %r" % (zone['name'], response.content)
            continue
        zone['records'] = response.json()

    for zone in zones.values():
        ips = filter(lambda x: x['name'].endswith("." + zone['name']), addresses)
        def find_or_max(name, zone):
            try:
                if not name.endswith('.' + zone):
                    raise Exception("no match")
                return name.index('.' + zone)
            except:
                return sys.maxint
        zone['records'].extend([{
            'name': ip['name'],
            'zone': zone['name'],
            'type': 'A',
            'value': [ip['ip']],
            'ttl': ip.get('ttl', ''),
        } for ip in ips if zone['name'] == sorted(zones.keys(), key=lambda z: find_or_max(ip['name'], z))[0]])
        for ip in ips:
            reverse_name = dns.reversename.from_address(ip['ip'])
            reverse_zone = str(reverse_name.split(6)[1])[:-1]
            if reverse_zone in not_my_zones:
                continue
            if reverse_zone not in zones:
                zones[reverse_zone] = {'name': reverse_zone, 'records': []}
            zones[reverse_zone]['records'].append({
                'name': str(reverse_name)[:-1],
                'zone': reverse_zone,
                'type': 'PTR',
                'value': [ip['name'] + '.'],
                'ttl': ip.get('ttl', ''),
            })

    flattened = []
    for zone in zones.itervalues():
        into = zone.get('tags', {}).get('flatten', None)
        if into is not None and into in zones:
            zones[into]['records'].extend(zone['records'])
            flattened.append(zone['name'])

    for name in flattened:
        zones.pop(name)

    logging.basicConfig(level=logging.DEBUG)
    isc = iscBonk(config)
    named_slave_conf_path = None
    if config.has_option("iscbrf", "named_slave_conf_path"):
        named_slave_conf_path = config.get("iscbrf", "named_slave_conf_path")
    isc.buildBindConfig(zones, config.get("iscbrf", "named_conf_path"), named_slave_conf_path)
    isc.buildDhcpdConfig(prefixes, addresses, config.get("iscbrf", "dhcpd_conf_path"))
