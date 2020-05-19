#!/usr/bin/env python3

# Copyright 2017 Klarna Bank AB
# Copyright 2020 Qliro AB
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
import time
import hashlib
import hmac
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin


class iscBonk(object):

    def __init__(self, config):
        template_dir = 'templates/'
        if config.has_option('iscbrf', 'template_dir'):
            template_dir = config.get('iscbrf', 'template_dir')
        self.named_template = os.path.join(template_dir, 'named.conf.j2')
        self.named_slave_template = os.path.join(template_dir, 'named-slave.conf.j2')
        self.dhcpd_template = os.path.join(template_dir, 'dhcpd.conf.j2')
        self.zone_template = os.path.join(template_dir, 'zone.j2')
        self.cache_path = '/var/cache/bind/'
        if config.has_option('iscbrf', 'cache_path'):
            self.cache_path = config.get('iscbrf', 'cache_path')
        self.zone_path = '/etc/named/pri/'
        if config.has_option('iscbrf', 'zone_path'):
            self.zone_path = config.get('iscbrf', 'zone_path')
        self.zone_output_path = '/etc/named/pri/'
        if config.has_option('iscbrf', 'zone_output_path'):
            self.zone_output_path = config.get('iscbrf', 'zone_output_path')
        self.default_soa = {
            'authns': config.get('default_soa', 'authns'),
            'email': config.get('default_soa', 'email'),
            'refresh': config.getint('default_soa', 'refresh'),
            'retry': config.getint('default_soa', 'retry'),
            'expiry': config.getint('default_soa', 'expiry'),
            'nxdomain': config.getint('default_soa', 'nxdomain'),
        }
        self.default_ns = [config.get('default_ns', option) for option in config.options('default_ns')]
        if config.has_section('slave_masters'):
            self.slave_masters = [config.get('slave_masters', option) for option in config.options('slave_masters')]
        else:
            self.slave_masters = []
        self.serial_method = 'increase'
        if config.has_option('iscbrf', 'serial_method'):
            self.serial_method = config.get('iscbrf', 'serial_method')
        self.log = logging.getLogger(__name__)

    def buildDhcpdConfig(self, prefixes, addresses, outfile=None):
        r = None
        j2 = jinja2.Environment(
            loader=jinja2.FileSystemLoader(
                os.path.dirname(os.path.abspath(self.dhcpd_template))
            ),
            trim_blocks=True,
            lstrip_blocks=True)
        j2.filters['netmask'] = lambda x: netaddr.IPNetwork('127.0.0.0/%d' % x).netmask

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

    def increaseSerial(self, serial):
        if self.serial_method == 'increase':
            return serial + 1
        elif self.serial_method == 'date':
            date = time.strftime("%Y%m%d")
            if str(serial).startswith(date):
                return date + ("%02d" % ((serial % 100) + 1))
            else:
                return date + "01"

    def makeZoneFile(self, zone, outfile=None):
        r = None
        # sort the record list by record name if it exists
        for record in zone['records']:
            if record['name'] == zone['name'] and record['type'] == 'NS':
                break
        else:
            zone['records'].append({'name': zone['name'], 'type': 'NS', 'value': self.default_ns})
        zone['records'] = sorted(zone['records'], key=lambda k: k['name'])

        # Split and format TXT records
        for record in zone['records']:
            if record['type'] == 'TXT':
                old_value = record['value']
                record['value'] = []
                for v in old_value:
                    if v.startswith('"'):
                        record['value'].append(v)
                    else:
                        for start in range(0, len(v), 254):
                            record['value'].append('"' + v[start:start + 254] + '"')

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

        r = j2.get_template(os.path.basename(self.zone_template)).render(zone=zone, serial=self.increaseSerial(serial))
        # Ensure that the zone can be understood by dnspython
        dns.zone.from_text(r, origin=zone['name'])

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


class akamaiBonk(object):
    def __init__(self, config):
        from akamai.edgegrid import EdgeGridAuth, EdgeRc
        self.config = config
        self.log = logging.getLogger(__name__)
        self.edgerc = EdgeRc(os.path.expanduser('~/.edgerc'))
        self.section = 'default'
        if config.has_option('akamai', 'section'):
            self.section = config.get('akamai', 'section')
        self.contract_id = config.get('akamai', 'contract_id')
        self.baseurl = 'https://%s' % self.edgerc.get(self.section, 'host')
        self.session = requests.Session()
        self.session.auth = EdgeGridAuth.from_edgerc(self.edgerc, self.section)
        self.dry_run = True
        if config.has_option('akamai', 'dry_run'):
            self.dry_run = config.getboolean('akamai', 'dry_run')

    def die(self, *args):
        self.log.error(*args)
        sys.exit(1)

    def uploadZones(self, zones):
        response = self.session.get(urljoin(self.baseurl, '/config-dns/v2/zones?showAll=true&types=primary'))
        if response.status_code != 200:
            self.die("Failed to list zones in Akamai: %d %s", response.status_code, response.text)
        existing_zone_list = [z['zone'] for z in response.json()['zones']]

        # Create new zones
        for zone in set(zones.keys()) - set(existing_zone_list):
            self.log.info("Creating zone %s", zone)
            if not self.dry_run:
                response = self.session.post(urljoin(self.baseurl, '/config-dns/v2/zones?contractId=%s' % self.contract_id), json={
                    "zone": zone,
                    "type": "primary",
                })
                if response.status_code not in (200, 201):
                    self.die("Failed to create zone %s in Akamai: %d %s", zone, response.status_code, response.text)

        # Delete old zones
        for zone in set(existing_zone_list) - set(zones.keys()):
            self.log.info("Deleting zone %s (not implemented)", zone)

        # Compare records
        def akamaize_record(r, default_ttl=86400):
            ret = {
                'name': r['name'],
                'rdata': r['value'],
                'type': r['type'],
                'ttl': r.get('ttl', default_ttl)
            }
            if r['type'] == 'ANAME':
                ret['type'] = 'AKAMAICDN'
                ret['rdata'] = [v.rstrip('.') for v in r['value']]
                ret['ttl'] = 20
            return ret
        for zone in zones.keys():
            changes = []

            response = self.session.get(urljoin(self.baseurl, '/config-dns/v2/zones/%s/recordsets?sortBy=name,type&showAll=true' % zone))
            if response.status_code != 200:
                self.die("Failed to list RRsets in zone %s: %d %s", zone, response.status_code, response.text)
            existing_rrsets = response.json()['recordsets']

            bonk_as_akamai = [akamaize_record(r, zones[zone].get('ttl', 86400)) for r in zones[zone]['records']]

            # Find new/changed records
            for rrset in bonk_as_akamai:
                if rrset not in existing_rrsets:
                    # See if this is a change or an addition
                    op = None
                    for existing_rrset in existing_rrsets:
                        if existing_rrset['name'] == rrset['name'] and existing_rrset['type'] == rrset['type']:
                            op = "EDIT"
                            self.log.debug("Replacing record %s %s with %r, was %r", rrset['name'], rrset['type'], rrset, existing_rrset)
                            break
                    else:
                        op = "ADD"
                        self.log.debug("Adding record %s %s with %r", rrset['name'], rrset['type'], rrset['rdata'])

                    changes.append({
                        "op": op,
                        "name": rrset['name'],
                        "type": rrset['type'],
                        "ttl": rrset['ttl'],
                        "rdata": rrset['rdata'],
                    })

            # Find deleted records
            for existing_rrset in existing_rrsets:
                if existing_rrset not in bonk_as_akamai:
                    if existing_rrset['type'] == 'SOA':
                        continue
                    for rrset in bonk_as_akamai:
                        if existing_rrset['name'] == rrset['name'] and existing_rrset['type'] == rrset['type']:
                            break
                    else:
                        self.log.debug("Deleting record %s %s, was %r", existing_rrset['name'], existing_rrset['type'], existing_rrset['rdata'])
                        changes.append({
                            "op": "DELETE",
                            "name": existing_rrset['name'],
                            "type": existing_rrset['type'],
                        })

            if not self.dry_run and len(changes) > 0:
                response = self.session.post(urljoin(self.baseurl, '/config-dns/v2/changelists?zone=%s&overwrite=any' % zone), json={
                })
                if response.status_code != 201:
                    self.die("Unable to create changelist for zone %s: %d %s", zone, response.status_code, response.text)
                for change in changes:
                    response = self.session.post(urljoin(self.baseurl, '/config-dns/v2/changelists/%s/recordsets/add-change' % zone), json=change)
                    if response.status_code != 204:
                        self.die("Unable to add change to changelist for zone %s: %d %s", zone, response.status_code, response.text)

                response = self.session.post(urljoin(self.baseurl, '/config-dns/v2/changelists/%s/submit' % zone))
                if response.status_code != 204:
                    self.die("Unable to submit changelist for zone %s: %d %s", zone, response.status_code, response.text)


class dnsmeBonk(object):
    def __init__(self, config):
        self.config = config
        self.log = logging.getLogger(__name__)
        self.dry_run = True
        self.baseurl = 'https://api.dnsmadeeasy.com/V2.0/'
        if config.has_option('dnsmadeeasy', 'baseurl'):
            self.baseurl = config.get('dnsmadeeasy', 'baseurl')
        self.api_key = config.get('dnsmadeeasy', 'api_key')
        self.secret_key = config.get('dnsmadeeasy', 'secret_key')
        if config.has_option('dnsmadeeasy', 'dry_run'):
            self.dry_run = config.getboolean('dnsmadeeasy', 'dry_run')
        try:
            with open(os.path.expanduser('~/.dnsme-req.json')) as f:
                self.requests = json.load(f)
        except:
            self.requests = []

    def die(self, *args):
        self.log.error(*args)
        sys.exit(1)

    def sign(self):
        signed_date = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
        return {
            'x-dnsme-apiKey': self.api_key,
            'x-dnsme-requestDate': signed_date,
            'x-dnsme-hmac': hmac.new(self.secret_key.encode('ascii'), signed_date.encode('ascii'), hashlib.sha1).hexdigest(),
            'accept': 'application/json',
            'content-type': 'application/json',
        }

    def request(self, method, url, json=None, params=None):
        # Ensure we never use more than 150 requests per 5 minutes
        now = time.time()
        self.requests = [r for r in self.requests if r > now - 300]
        self.requests.append(time.time())
        if len(self.requests) > 140:
            time.sleep(300 - (now - self.requests[0]))
        return getattr(requests, method)(urljoin(self.baseurl, url), headers=self.sign(), json=json, params=params)

    def uploadZones(self, zones):
        response = self.request('get', 'dns/managed/')
        if response.status_code != 200:
            self.die("Failed to list zones in DNS Made Easy: %d %s", response.status_code, response.text)
        existing_zone_list = dict([(z['name'], z['id']) for z in response.json()['data']])

        # Create new zones
        for zone in set(zones.keys()) - set(existing_zone_list.keys()):
            self.log.info("Creating zone %s", zone)
            if not self.dry_run:
                response = self.request('post', 'dns/managed/', json={'name': zone})
                if response.status_code not in (200, 201):
                    self.die("Failed to create zone %s in DNS Made Easy: %d %s", zone, response.status_code, response.text)
                existing_zone_list[zone] = response.json()['id']

        # Delete old zones
        for zone in set(existing_zone_list.keys()) - set(zones.keys()):
            self.log.info("Deleting zone %s")
            if not self.dry_run:
                response = self.request('delete', 'dns/managed/', json=[existing_zone_list[zone]])
                if response.status_code != 204:
                    self.die("Failed to delete zone %s in DNS Made Easy: %d %s", zone, response.status_code, response.text)

        # Compare records
        def dnsme_name(name, zone):
            if name.endswith(zone):
                return name[:-len(zone)].rstrip(".")
            else:
                return name

        def dnsme_compare(zone, rrset, rdata, value=None):
            if (dnsme_name(rrset['name'], zone) == rdata['name']
                and rrset['type'] == rdata['type']):
                if rrset['type'] == 'MX':
                    dnsme_value = "%d %s" % (rdata['mxLevel'], rdata['value'])
                elif rrset['type'] == 'SRV':
                    dnsme_value = "%d %d %d %s" % (rdata['priority'], rdata['weight'], rdata['port'], rdata['value'])
                else:
                    dnsme_value = rdata['value']
                if value is not None:
                    return value == dnsme_value
                else:
                    return dnsme_value in rrset['value']
            return False
        response = self.request('get', 'dns/vanity')
        if response.status_code != 200:
            self.die("Failed to fetch available vanity nameservers: %d %s", response.status_code, response.text)
        vanities = response.json()['data']
        for zone in zones.keys():
            if zone in existing_zone_list:
                response = self.request('get', 'dns/managed/%d/records/' % existing_zone_list[zone])
                if response.status_code != 200:
                    self.die("Failed to list records in domain %s: %d %s", zone, response.status_code, response.text)
                existing_rdatas = response.json()['data']
            else:
                existing_rdatas = []

            # Delete changed records
            # Changes are handled as a deletion followed by an addition
            to_delete = []
            for rrset in zones[zone]['records']:
                for existing_rdata in existing_rdatas:
                    if (dnsme_name(rrset['name'], zone) == existing_rdata['name']
                        and rrset['type'] == existing_rdata['type']):
                        if not dnsme_compare(zone, rrset, existing_rdata):
                            self.log.debug("Deleting record %s %s, was %r", existing_rdata['name'], existing_rdata['type'], existing_rdata['value'])
                            to_delete.append(existing_rdata['id'])

            # Delete old records
            for existing_rdata in existing_rdatas:
                for rrset in zones[zone]['records']:
                    if dnsme_compare(zone, rrset, existing_rdata):
                        break
                else:
                    self.log.debug("Deleting record %s %s, was %r", existing_rdata['name'], existing_rdata['type'], existing_rdata['value'])
                    to_delete.append(existing_rdata['id'])

            if not self.dry_run and len(to_delete) > 0:
                response = self.request('delete', 'dns/managed/%s/records' % existing_zone_list[zone], params={'ids': to_delete})
                if response.status_code not in (200, 204):
                    self.die("Failed to delete records from zone %s: %d %s", zone, response.status_code, response.text)

            # Add new records
            to_add = []
            for rrset in zones[zone]['records']:
                for value in rrset['value']:
                    for existing_rdata in existing_rdatas:
                        if dnsme_compare(zone, rrset, existing_rdata, value):
                            break
                    else:
                        self.log.debug("Adding record %s %s %s", rrset['name'], rrset['type'], value)
                        if not self.dry_run:
                            dnsme_record = {
                                'name': dnsme_name(rrset['name'], zone),
                                'type': rrset['type'],
                                'gtdLocation': 'DEFAULT',
                                'ttl': rrset.get('ttl', zones[zone].get('ttl', 86400)),
                            }
                            if rrset['type'] == 'MX':
                                dnsme_record['mxLevel'], dnsme_record['value'] = value.split()
                                dnsme_record['mxLevel'] = int(dnsme_record['mxLevel'])
                            elif rrset['type'] == 'SRV':
                                dnsme_record['priority'], dnsme_record['weight'], dnsme_record['port'], dnsme_record['value'] = [int(x) if x.isnumeric() else x for x in value.split()]
                            else:
                                dnsme_record['value'] = value
                            to_add.append(dnsme_record)

            if not self.dry_run and len(to_add) > 0:
                response = self.request('post', 'dns/managed/%d/records/createMulti' % (existing_zone_list[zone]), json=to_add)
                if response.status_code not in (200, 201):
                    self.die("Failed to create records for zone %s in DNS Made Easy: %d %s", zone, response.status_code, response.text)

            # Set vanity nameserver configuration if needed
            # Primarily needed to use less nameservers for registries with low limits
            nameservers = [rrset for rrset in zones[zone]['records'] if rrset['type'] == 'NS']
            if len(nameservers) > 0:
                response = self.request('get', 'dns/managed/%d' % (existing_zone_list[zone]))
                if response.status_code != 200:
                    self.die("Failed to get domain %s in DNS Made Easy: %d %s", zone, response.status_code, response.text)
                domain = response.json()
                dnsme_real_ns = [ns.strip('.') for ns in nameservers[0]['value'] if 'dnsmadeeasy' in ns]
                dnsme_serving_group = domain['nameServers'][0]['groupId']
                desired_vanity_id = [v['id'] for v in vanities if v['nameServerGroupId'] == dnsme_serving_group and v['servers'] == dnsme_real_ns]
                if len(desired_vanity_id) > 0:
                    if 'vanityId' not in domain or domain['vanityId'] != desired_vanity_id[0]:
                        self.log.debug("Updating vanity configuration to %d from %d on %s", desired_vanity_id[0], domain.get('vanityId', -1), zone)
                        if not self.dry_run:
                            response = self.request('put', 'dns/managed/%d' % existing_zone_list[zone], json={'vanityId': "%d" % desired_vanity_id[0]})
                            if response.status_code != 200:
                                self.die("Failed to set vanity configuration on zone %s: %d %s", zone, response.status_code, response.text)

        with open(os.path.expanduser('~/.dnsme-req.json'), 'w') as f:
            json.dump(self.requests, f)


if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s %(message)s',
        level=logging.DEBUG
    )
    logger = logging.getLogger(__name__)

    config = ConfigParser.SafeConfigParser()
    config.read(sys.argv[1:])
    server = config.get('api', 'uri')
    username = config.get('api', 'username')
    password = config.get('api', 'password')
    auth = (username, password)
    my_type = config.get('iscbrf', 'type')
    output_class = config.get('iscbrf', 'output_class')
    auto_reverse = config.get('iscbrf', 'auto_reverse')

    response = requests.get(server + 'zone/', params={'type': my_type}, auth=auth)
    if response.status_code != 200:
        logger.error('Failed to get my zones: {0}'.format(response.content))
        sys.exit(1)
    zones = dict([(zone['name'], zone) for zone in response.json()])

    response = requests.get(server + 'zone/', auth=auth)
    if response.status_code != 200:
        logger.error('Failed to get all zones: {0}'.format(response.content))
        sys.exit(1)
    not_my_zones = set([zone['name'] for zone in response.json() if zone['name'] not in zones])

    response = requests.get(server + 'prefix/', auth=auth)
    if response.status_code != 200:
        logger.error('Failed to get prefixes: {0}'.format(response.content))
        sys.exit(1)
    prefixes = response.json()

    response = requests.get(server + 'address/', params={'state': 'allocated'}, auth=auth)
    if response.status_code != 200:
        logger.error('Failed to get addresses: {0}'.format(response.content))
        sys.exit(1)
    addresses = response.json()

    for zone in zones.values():
        response = requests.get(server + 'record/', params={'zone': zone['name']}, auth=auth)
        if response.status_code != 200:
            logger.warning('Failed to get DNS records for {0}: {1}'.format(zone['name'], response.content))
            continue
        zone['records'] = response.json()

    for zone in list(zones.values()):
        if zone['name'].endswith(".arpa"):
            if zone['name'].endswith(".in-addr.arpa"):
                network = ".".join(zone['name'].split(".")[:3][::-1]) + "."
            elif zone['name'].endswith(".ip6.arpa"):
                network = zone['name'].split(".")[:-2][::-1]
                network = ":".join(["".join(network[i:i + 4]) for i in range(0, len(network), 4)])
            ips = list(filter(lambda x: x['ip'].startswith(network), addresses))
        else:
            def find_or_max(name, zone):
                try:
                    if not name.endswith('.' + zone):
                        raise Exception('no match')
                    return name.index('.' + zone)
                except:
                    return sys.maxsize
            ips = [ip for ip in addresses if zone['name'] == sorted(list(zones.keys()) + list(not_my_zones), key=lambda z: find_or_max(ip['name'], z))[0]]
            zone['records'].extend([{
                'name': ip['name'],
                'zone': zone['name'],
                'type': 'A',
                'value': [ip['ip']],
                'ttl': ip.get('ttl', ''),
            } for ip in ips])

        for ip in ips:
            reverse_name = dns.reversename.from_address(ip['ip'])
            reverse_zone = str(reverse_name.split(6)[1])[:-1]
            if reverse_zone in not_my_zones:
                continue
            if reverse_zone not in zones and auto_reverse:
                zones[reverse_zone] = {'name': reverse_zone, 'records': []}
            elif reverse_zone not in zones:
                continue
            for record in zones[reverse_zone]['records']:
                if record['name'] == str(reverse_name)[:-1]:
                    break
            else:
                zones[reverse_zone]['records'].append({
                    'name': str(reverse_name)[:-1],
                    'zone': reverse_zone,
                    'type': 'PTR',
                    'value': [ip['name'] + '.'],
                    'ttl': ip.get('ttl', ''),
                })

    flattened = []
    for zone in zones.values():
        into = zone.get('tags', {}).get('flatten', None)
        if into is not None and into in zones:
            zones[into]['records'].extend(zone['records'])
            flattened.append(zone['name'])

    for name in flattened:
        zones.pop(name)

    if output_class == 'akamaiBonk':
        akamai = akamaiBonk(config)
        akamai.uploadZones(zones)
    elif output_class == 'dnsmeBonk':
        dnsme = dnsmeBonk(config)
        dnsme.uploadZones(zones)
    else:
        isc = iscBonk(config)
        named_slave_conf_path = None
        if config.has_option('iscbrf', 'named_slave_conf_path'):
            named_slave_conf_path = config.get('iscbrf', 'named_slave_conf_path')
        isc.buildBindConfig(zones, config.get('iscbrf', 'named_conf_path'), named_slave_conf_path)
        isc.buildDhcpdConfig(prefixes, addresses, config.get('iscbrf', 'dhcpd_conf_path'))
