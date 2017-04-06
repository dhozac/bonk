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

from django.conf import settings
from django.contrib.auth.models import Group
from rest_framework import serializers
import netaddr
import re
from django_rethink import r, RethinkSerializer, RethinkObjectNotFound, RethinkMultipleObjectsFound, validate_unique_key, get_connection, HistorySerializerMixin

def validate_group_name(group_name):
    try:
        group = Group.objects.get(name=group_name)
        return True
    except Group.DoesNotExist:
        if hasattr(settings, 'AUTH_LDAP_SERVER_URI'):
            import ldap
            l = ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
            if settings.AUTH_LDAP_START_TLS:
                l.start_tls_s()
            result = settings.AUTH_LDAP_GROUP_SEARCH.search_with_additional_term_string("(cn=%s)").execute(l, filterargs=(group_name,))
            if len(result) > 0:
                return True
        raise serializers.ValidationError("group %s does not exist" % group_name)

def filter_in_subnet(ip, network):
    return lambda row: r.js("(" +
            r.map(
                r.expr(row[ip._args[1].data] if isinstance(ip, r.ast.Bracket) and str(ip).startswith("r.row") else ip).split(".").map(lambda octet: octet.coerce_to("number")),
                [1 << 24, 1 << 16, 1 << 8, 1], lambda octet, multiplier: octet * multiplier).
            sum().coerce_to("string") + " & ~(Math.pow(2, 32 - " +
            r.expr(row if str(network) == 'r.row' else network)['length'].coerce_to("string") + ") - 1)) == (" +
            r.map(
                r.expr(row if str(network) == 'r.row' else network)['network'].split(".").map(lambda octet: octet.coerce_to("number")),
                [1 << 24, 1 << 16, 1 << 8, 1], lambda octet, multiplier: octet * multiplier).
            sum().coerce_to("string") +
            " & ~0)"
        )

class VRFSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True)
    name = serializers.CharField(required=True)

    class Meta(RethinkSerializer.Meta):
        table_name = 'vrf'
        slug_field = 'vrf'
        indices = [
            'vrf',
        ]

def validate_vrf(value):
    try:
        VRFSerializer.get(vrf=value)
    except:
        raise serializers.ValidationError("vrf=%r doesn't exist" % value)
    return value

class IPBlockSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True, validators=[validate_vrf])
    network = serializers.IPAddressField(required=True)
    length = serializers.IntegerField(required=True)
    announced_by = serializers.CharField(required=False)
    allocators = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False, allow_empty=True)

    class Meta(RethinkSerializer.Meta):
        table_name = 'ip_block'
        slug_field = 'vrf_network_length'
        indices = [
            ('vrf_network_length', (r.row['vrf'], r.row['network'], r.row['length'])),
            ('allocators', {'multi': True}),
        ]
        unique_together = [
            ('vrf', 'network', 'length'),
        ]

    @classmethod
    def get_by_ip(cls, vrf, ip, reql=False):
        query = cls.filter(filter_in_subnet(ip, r.row), reql=True) \
                .filter({'vrf': vrf}) \
                .order_by(r.desc("length")).nth(0)
        if reql:
            return query
        else:
            try:
                return query.run(get_connection())
            except r.errors.ReqlNonExistenceError:
                raise RethinkObjectNotFound("no block found for IP %s" % ip)

    def validate(self, data):
        data = super(IPBlockSerializer, self).validate(data)
        full = self.get_updated_object(data)
        network = netaddr.IPNetwork("%s/%d" % (full['network'], full['length']))
        if str(network.network) != full['network']:
            raise serializers.ValidationError("network is not the network address for %s/%d" % (full['network'], full['length']))
        return data

class IPPrefixDHCPSerializer(serializers.Serializer):
    enabled = serializers.BooleanField(required=True)
    range = serializers.ListField(child=serializers.IPAddressField(), required=False)
    options = serializers.ListField(child=serializers.CharField(), required=False)

    def validate_range(self, value):
        if value and len(value) != 2:
            raise serializers.ValidationError("range must have a start and end address")
        return value

class DDNSSerializer(serializers.Serializer):
    zone = serializers.CharField(required=True)
    algorithm = serializers.CharField(required=True)
    key = serializers.CharField(required=True)

class IPPrefixDDNSSerializer(DDNSSerializer):
    server = serializers.IPAddressField(required=True)

class IPPrefixSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True, validators=[validate_vrf])
    network = serializers.IPAddressField(required=True)
    length = serializers.IntegerField(required=True)
    asn = serializers.IntegerField(required=False)
    state = serializers.ChoiceField(required=True, choices=['allocated', 'reserved', 'quarantine'])
    managers = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False, allow_empty=True)
    dhcp = IPPrefixDHCPSerializer(required=False)
    ddns = IPPrefixDDNSSerializer(required=False)
    reference = serializers.CharField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'ip_prefix'
        slug_field = 'vrf_network_length'
        indices = [
            ('vrf_network_length', (r.row['vrf'], r.row['network'], r.row['length'])),
            ('managers', {'multi': True}),
        ]
        unique_together = [
            ('vrf', 'network', 'length'),
        ]

    @classmethod
    def filter_by_block(cls, block, reql=False):
        return cls.filter(filter_in_subnet(r.row['network'], block), reql=reql)

    @classmethod
    def get_by_ip(cls, vrf, ip, reql=False):
        query = cls.filter(filter_in_subnet(ip, r.row), reql=True) \
                .filter({'vrf': vrf}) \
                .order_by(r.desc("length")).nth(0)
        if reql:
            return query
        else:
            try:
                return query.run(get_connection())
            except r.errors.ReqlNonExistenceError:
                raise RethinkObjectNotFound("no prefix found for IP %s" % ip)

    def validate(self, data):
        data = super(IPPrefixSerializer, self).validate(data)
        full = self.get_updated_object(data)
        try:
            block = IPBlockSerializer.get_by_ip(full['vrf'], full['network'])
        except RethinkObjectNotFound:
            raise serializers.ValidationError("no block exists matching prefix %s/%d" % (full['network'], full['length']))
        if block['length'] > full['length']:
            raise serializers.ValidationError("prefix %s/%d exceeds block of %s/%d" % (full['network'], full['length'], block['network'], block['length']))
        underlappers = filter(lambda x: x[self.Meta.pk_field] != full.get(self.Meta.pk_field, None), self.filter_by_block(full))
        if len(underlappers) > 0:
            raise serializers.ValidationError("prefix %s/%d overlaps with %r" % (full['network'], full['length'], underlappers))
        try:
            overlapper = IPPrefixSerializer.get_by_ip(full['vrf'], full['network'])
            raise serializers.ValidationError("prefix %s/%d includes this prefix %s/%d" % (overlapper['network'], overlapper['length'], full['network'], full['length']))
        except RethinkObjectNotFound:
            pass
        network = netaddr.IPNetwork("%s/%d" % (full['network'], full['length']))
        if str(network.network) != full['network']:
            raise serializers.ValidationError("network is not the network address for %s/%d" % (full['network'], full['length']))
        return data

validate_mac_re = re.compile(r'^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
def validate_mac(value):
    return validate_mac_re.match(value) is not None

class IPAddressSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    state = serializers.ChoiceField(required=True, choices=['allocated', 'reserved', 'quarantine'])
    vrf = serializers.IntegerField(required=True, validators=[validate_vrf])
    ip = serializers.IPAddressField(required=True)
    name = serializers.CharField(required=True)
    dhcp_mac = serializers.ListField(child=serializers.CharField(validators=[validate_mac]), required=False)
    reference = serializers.CharField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'ip_address'
        slug_field = 'vrf_ip'
        indices = [
            'ip',
            'name',
            ('vrf_ip', (r.row['vrf'], r.row['ip'])),
        ]
        unique_together = [
            ('vrf', 'ip'),
        ]

    @classmethod
    def filter_by_prefix(cls, prefix, reql=False):
        return cls.filter(filter_in_subnet(r.row['ip'], prefix), reql=reql)

    def validate_name(self, value):
        possibles = []
        for part in value.split(".")[:0:-1]:
            suffix = "" if len(possibles) == 0 else ("." + possibles[-1])
            possibles.append(part + suffix)
        try:
            zone = DNSZoneSerializer.filter(lambda zone: r.expr(possibles).contains(zone['name']), reql=True).order_by(r.desc(r.row['name'].count())).nth(0).run(self.conn)
        except r.errors.ReqlNonExistenceError:
            raise serializers.ValidationError("no zone matching %s could be found" % value)
        if 'request' in self.context and not self.context['request'].user.is_superuser:
            user_groups = set(self.context['request'].user.groups.all().values_list('name', flat=True))
            if len(user_groups.intersection(set(zone['managers']))) == 0:
                raise serializers.ValidationError("you do not have permission to create names in %s" % zone['name'])
        try:
            ip_address = IPAddressSerializer.get(name=value)
            if self.instance is None or ip_address['id'] != self.instance['id']:
                raise serializers.ValidationError("%r is already in use by %s" % (value, ip_address['ip']))
        except RethinkObjectNotFound:
            pass
        return value

    def validate(self, data):
        data = super(IPAddressSerializer, self).validate(data)
        full = self.get_updated_object(data)
        try:
            prefix = IPPrefixSerializer.get_by_ip(full['vrf'], full['ip'])
        except RethinkObjectNotFound:
            raise serializers.ValidationError("no prefix found for IP %s" % full['ip'])
        return data

class DNSZoneOptionsSerializer(serializers.Serializer):
    ddns = DDNSSerializer(required=False)
    forwarders = serializers.ListField(child=serializers.IPAddressField(), required=False)
    notify = serializers.ListField(child=serializers.IPAddressField(), required=False)
    masters = serializers.ListField(child=serializers.IPAddressField(), required=False)

class DNSZoneSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    needs_review = serializers.BooleanField(required=False, default=False)
    managers = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False)
    type = serializers.ChoiceField(required=True, choices=['internal', 'external'])
    name = serializers.CharField(required=True)
    options = DNSZoneOptionsSerializer(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'dns_zone'
        slug_field = 'name'
        indices = [
            'name',
            ('managers', {'multi': True}),
        ]
        unique = [
            'name',
        ]

class DNSRecordSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    name = serializers.CharField(required=True)
    zone = serializers.CharField(required=True)
    type = serializers.ChoiceField(choices=['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT'], required=True)
    ttl = serializers.IntegerField(required=False)
    value = serializers.ListField(child=serializers.CharField())
    reference = serializers.CharField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'dns_record'
        slug_field = 'name_type'
        indices = [
            'name',
            'zone',
            ('name_type', (r.row['name'], r.row['type'])),
            ('value', {'multi': True}),
        ]
        unique_together = [
            ('name', 'type'),
        ]

    def validate_zone(self, value):
        try:
            zone = DNSZoneSerializer.get(name=value)
        except RethinkObjectNotFound:
            raise serializers.ValidationError("'%s' does not exist" % value)
        if 'request' in self.context and not self.context['request'].user.is_superuser:
            user_groups = set(self.context['request'].user.groups.all().values_list('name', flat=True))
            if len(user_groups.intersection(set(zone['managers']))) == 0:
                raise serializers.ValidationError("you do not have permission to create names in %s" % zone['name'])
        return value

    def validate(self, data):
        data = super(DNSRecordSerializer, self).validate(data)
        full = self.get_updated_object(data)
        if full['name'] != full['zone'] and not full['name'].endswith('.' + full['zone']):
            raise serializers.ValidationError("name %s is not in zone %s" % (full['name'], full['zone']))
        # FIXME: Add validation of value for type
        if full['type'] == 'CNAME':
            records = list(DNSRecordSerializer.filter(name=full['name']))
            if self.instance is not None:
                records = filter(lambda x: x['id'] != self.instance['id'], records)
            if len(records) > 0:
                raise serializers.ValidationError("a CNAME record cannot be used on a name with any other record type")
        else:
            records = list(DNSRecordSerializer.filter(name=full['name'], type='CNAME'))
            if self.instance is not None:
                records = filter(lambda x: x['id'] != self.instance['id'], records)
            if len(records) > 0:
                raise serializers.ValidationError("a CNAME record exists for the specified name already")
        return data
