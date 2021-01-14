# Copyright 2017 Klarna Bank AB
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

from __future__ import absolute_import
from django.conf import settings
from django.contrib.auth.models import Group
from rest_framework import serializers
from rest_framework.reverse import reverse
import netaddr
import dns.zone
import re
from django_rethink import r, RethinkSerializer, RethinkObjectNotFound, RethinkMultipleObjectsFound, validate_unique_key, get_connection, HistorySerializerMixin, NeedsReviewMixin, PermissionsSerializer
from django_rethink.tasks import rethinkdb_lock, rethinkdb_unlock


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


class BonkTriggerMixin(object):
    def create(self, data):
        import bonk.tasks
        data = super(BonkTriggerMixin, self).create(data)
        task = rethinkdb_lock.s(name='trigger_dns_dhcp_rebuild') | \
            bonk.tasks.trigger_dns_dhcp_rebuild.si(data) | \
            rethinkdb_unlock.si(name='trigger_dns_dhcp_rebuild')
        task.apply_async()
        return data

    def update(self, instance, data):
        import bonk.tasks
        data = super(BonkTriggerMixin, self).update(instance, data)
        task = rethinkdb_lock.s(name='trigger_dns_dhcp_rebuild') | \
            bonk.tasks.trigger_dns_dhcp_rebuild.si(data) | \
            rethinkdb_unlock.si(name='trigger_dns_dhcp_rebuild')
        task.apply_async()
        return data

    def delete(self):
        import bonk.tasks
        ret = super(BonkTriggerMixin, self).delete()
        task = rethinkdb_lock.s(name='trigger_dns_dhcp_rebuild') | \
            bonk.tasks.trigger_dns_dhcp_rebuild.si(self.instance) | \
            rethinkdb_unlock.si(name='trigger_dns_dhcp_rebuild')
        task.apply_async()
        return ret


class VRFSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True)
    name = serializers.CharField(required=True)

    class Meta(RethinkSerializer.Meta):
        table_name = 'vrf'
        slug_field = 'vrf'
        indices = [
            'vrf',
        ]

    def create_link(self, instance):
        return reverse('bonk:vrf_detail', kwargs={
                'vrf': instance['vrf']
            }, request=self.context.get('request'))


def validate_vrf(value):
    try:
        VRFSerializer.get(vrf=value)
    except:
        raise serializers.ValidationError("vrf=%r doesn't exist" % value)
    return value


class IPBlockSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True, validators=[validate_vrf])
    network = serializers.IPAddressField(required=True)
    length = serializers.IntegerField(required=True)
    announced_by = serializers.CharField(required=False)
    permissions = PermissionsSerializer(required=False)
    name = serializers.CharField(required=True)

    class Meta(RethinkSerializer.Meta):
        table_name = 'ip_block'
        slug_field = 'vrf_network_length'
        indices = [
            'name',
            ('vrf_network_length', (r.row['vrf'], r.row['network'], r.row['length'])),
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]
        unique = [
            'name'
        ]
        unique_together = [
            ('vrf', 'network', 'length'),
        ]

    def create_link(self, instance):
        return reverse('bonk:block_detail', kwargs={
                'vrf': instance['vrf'],
                'network': instance['network'],
                'length': instance['length'],
            }, request=self.context.get('request'))

    @classmethod
    def get_by_ip(cls, vrf, ip, reql=False):
        query = cls.filter(lambda b:
                    r.ip_prefix_contains(
                        r.ip_prefix(b['network'], b['length']),
                        r.ip_address(ip)
                    ), reql=True) \
                .filter({'vrf': vrf}) \
                .order_by(r.desc("length")).nth(0)
        if reql:
            return query
        else:
            try:
                return query.run(get_connection())
            except r.errors.ReqlNonExistenceError:
                raise RethinkObjectNotFound("no block found for IP %s" % ip)

    @classmethod
    def filter_by_block(cls, block, reql=False):
        return cls.filter(lambda b:
            r.ip_prefix_contains(
                r.ip_prefix(block['network'], block['length']),
                r.ip_address(b['network'])
            ), reql=reql)

    def validate(self, data):
        data = super(IPBlockSerializer, self).validate(data)
        full = self.get_updated_object(data)
        network = netaddr.IPNetwork("%s/%d" % (full['network'], full['length']))
        if str(network.network) != full['network']:
            raise serializers.ValidationError("network is not the network address for %s/%d" % (full['network'], full['length']))
        return data


class IPPrefixDHCPSerializer(serializers.Serializer):
    enabled = serializers.BooleanField(required=True)
    server_set = serializers.CharField(required=False)
    range = serializers.ListField(child=serializers.IPAddressField(), required=False)
    options = serializers.ListField(child=serializers.CharField(), required=False)

    def validate_range(self, value):
        if value and len(value) != 2:
            raise serializers.ValidationError("range must have a start and end address")
        return value

    def validate_server_set(self, value):
        try:
            DHCPServerSetSerializer.get(name=value)
        except RethinkObjectNotFound:
            raise serializers.ValidationError("server_set=%r doesn't exist" % value)
        return value


class DDNSSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    algorithm = serializers.CharField(required=True)
    key = serializers.CharField(required=True)


class IPPrefixDDNSSerializer(DDNSSerializer):
    zone = serializers.CharField(required=True)
    server = serializers.IPAddressField(required=True)


class IPPrefixSerializer(BonkTriggerMixin, HistorySerializerMixin):
    id = serializers.CharField(required=False)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True, validators=[validate_vrf])
    network = serializers.IPAddressField(required=True)
    length = serializers.IntegerField(required=True)
    asn = serializers.IntegerField(required=False)
    name = serializers.CharField(required=False)
    state = serializers.ChoiceField(required=True, choices=['allocated', 'reserved', 'quarantine'])
    permissions = PermissionsSerializer(required=False)
    gateway = serializers.IPAddressField(required=False)
    dhcp = IPPrefixDHCPSerializer(required=False)
    ddns = IPPrefixDDNSSerializer(required=False)
    reference = serializers.CharField(required=False)
    inventory_id = serializers.CharField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'ip_prefix'
        slug_field = 'vrf_network_length'
        indices = [
            'name',
            ('vrf_network_length', (r.row['vrf'], r.row['network'], r.row['length'])),
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]
        unique = [
            'name'
        ]
        unique_together = [
            ('vrf', 'network', 'length'),
        ]

    def create_link(self, instance):
        return reverse('bonk:prefix_detail', kwargs={
                'vrf': instance['vrf'],
                'network': instance['network'],
                'length': instance['length'],
            }, request=self.context.get('request'))

    @classmethod
    def filter_by_block(cls, block, reql=False):
        return cls.filter(lambda p:
            r.ip_prefix_contains(
                r.ip_prefix(block['network'], block['length']),
                r.ip_address(p['network'])
            ), reql=reql)

    @classmethod
    def get_by_ip(cls, vrf, ip, reql=False):
        query = cls.filter(lambda p:
                r.ip_prefix_contains(
                    r.ip_prefix(p['network'], p['length']),
                    r.ip_address(ip)
                ), reql=True) \
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
        if (self.instance is None
                and self.context['request'].user is not None
                and not self.context['request'].user.is_superuser
            ):
            allowed = set(
                block.get('permissions', {}).get('write', [])
                + block.get('permissions', {}).get('create', [])
            )
            groups = set(self.context['request'].user.groups.all().values_list('name', flat=True))
            if len(groups.intersection(allowed)) == 0:
                raise serializers.ValidationError("you do not have permissions to block %s/%d" % (block['network'], block['length']))
        underlappers = [x for x in self.filter_by_block(full) if x[self.Meta.pk_field] != full.get(self.Meta.pk_field, None)]
        if len(underlappers) > 0:
            raise serializers.ValidationError("prefix %s/%d overlaps with %r" % (full['network'], full['length'], underlappers))
        try:
            overlapper = IPPrefixSerializer.get_by_ip(full['vrf'], full['network'])
            if overlapper[self.Meta.pk_field] != full.get(self.Meta.pk_field, None):
                raise serializers.ValidationError("prefix %s/%d includes this prefix %s/%d" % (overlapper['network'], overlapper['length'], full['network'], full['length']))
        except RethinkObjectNotFound:
            pass
        network = netaddr.IPNetwork("%s/%d" % (full['network'], full['length']))
        if str(network.network) != full['network']:
            raise serializers.ValidationError("network is not the network address for %s/%d" % (full['network'], full['length']))
        return data

    def create(self, data):
        import bonk.tasks
        data = super(IPPrefixSerializer, self).create(data)
        block = IPBlockSerializer.get_by_ip(data['vrf'], data['network'])
        if 'announced_by' in block and data['state'] == 'allocated':
            bonk.tasks.trigger_prefix_create.apply_async((data, block))
        return data

    def update(self, instance, data):
        import bonk.tasks
        ret = super(IPPrefixSerializer, self).update(instance, data)
        block = IPBlockSerializer.get_by_ip(ret['vrf'], ret['network'])
        if 'announced_by' in block:
            if instance['state'] != 'allocated' and ret['state'] == 'allocated':
                bonk.tasks.trigger_prefix_create.apply_async((ret, block))
            elif instance['state'] == 'allocated' and ret['state'] != 'allocated':
                bonk.tasks.trigger_prefix_delete.apply_async((ret, block))
        return ret

    def delete(self):
        import bonk.tasks
        block = IPBlockSerializer.get_by_ip(self.instance['vrf'], self.instance['network'])
        if 'announced_by' in block and self.instance['state'] == 'allocated':
            bonk.tasks.trigger_prefix_delete.apply_async((self.instance, block))
        for address in IPAddressSerializer.filter_by_prefix(self.instance):
            ip = IPAddressSerializer(address)
            ip.delete()
        ret = super(IPPrefixSerializer, self).delete()
        return ret


validate_mac_re = re.compile(r'^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
def validate_mac(value):
    if validate_mac_re.match(value) is None:
        raise serializers.ValidationError("%s is not a valid MAC address (format as de:ad:be:ef:f0:00)" % value)


validate_fqdn_re = re.compile(r'^(([a-zA-Z0-9_][a-zA-Z0-9\-]*[a-zA-Z0-9]|[a-zA-Z0-9]|\*)\.)*([A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$')
def validate_fqdn(value):
    if validate_fqdn_re.match(value) is None:
        raise serializers.ValidationError("%s is not a valid FQDN" % value)


def validate_ttl(value):
    if value.bit_length() > 32:
        raise serializers.ValidationError("TTL can't be larger than 32 bits, value: %s" % value)
    if value < 0:
        raise serializers.ValidationError("TTL must be a positive value, value: %s")


class IPAddressSerializer(BonkTriggerMixin, HistorySerializerMixin):
    id = serializers.CharField(required=False)
    tags = serializers.DictField(required=False)
    state = serializers.ChoiceField(required=True, choices=['allocated', 'reserved', 'quarantine'])
    vrf = serializers.IntegerField(required=True, validators=[validate_vrf])
    ip = serializers.IPAddressField(required=True)
    name = serializers.CharField(required=True, validators=[validate_fqdn])
    dhcp_mac = serializers.ListField(child=serializers.CharField(validators=[validate_mac]), required=False)
    reference = serializers.CharField(required=False)
    permissions = PermissionsSerializer(required=False)
    ttl = serializers.IntegerField(required=False, validators=[validate_ttl])

    class Meta(RethinkSerializer.Meta):
        table_name = 'ip_address'
        slug_field = 'vrf_ip'
        indices = [
            'ip',
            'name',
            ('vrf_ip', (r.row['vrf'], r.row['ip'])),
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]
        unique_together = [
            ('vrf', 'ip'),
        ]

    def create_link(self, instance):
        return reverse('bonk:address_detail', kwargs={
                'vrf': instance['vrf'],
                'ip': instance['ip'],
            }, request=self.context.get('request'))

    @classmethod
    def filter_by_prefix(cls, prefix, reql=False):
        return cls.filter(lambda a:
            r.ip_prefix_contains(
                r.ip_prefix(prefix['network'], prefix['length']),
                r.ip_address(a['ip'])
            ),
        reql=reql)

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
            if self.instance is not None and len(user_groups.intersection(set(
                    self.instance.get('permissions', {}).get('write', [])
                ))) > 0:
                pass
            elif len(user_groups.intersection(set(
                    zone.get('permissions', {}).get('create', [])
                    + zone.get('permissions', {}).get('write', [])
                ))) == 0:
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


class DNSSOASerializer(serializers.Serializer):
    authns = serializers.CharField(required=True)
    email = serializers.CharField(required=True)
    refresh = serializers.IntegerField(required=True)
    retry = serializers.IntegerField(required=True)
    expiry = serializers.IntegerField(required=True)
    nxdomain = serializers.IntegerField(required=True)


class DNSZoneSerializer(NeedsReviewMixin, BonkTriggerMixin, HistorySerializerMixin):
    id = serializers.CharField(required=False)
    tags = serializers.DictField(required=False)
    needs_review = serializers.BooleanField(required=False, default=False)
    type = serializers.ChoiceField(required=True, choices=['internal', 'external'])
    name = serializers.CharField(required=True, validators=[validate_fqdn])
    soa = DNSSOASerializer(required=False)
    ttl = serializers.IntegerField(required=False, validators=[validate_ttl])
    options = DNSZoneOptionsSerializer(required=False)
    permissions = PermissionsSerializer(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'dns_zone'
        slug_field = 'name'
        needs_review_field = 'needs_review'
        indices = [
            'name',
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]
        unique = [
            'name',
        ]

    def create_link(self, instance):
        return reverse('bonk:zone_detail', kwargs={'slug': instance['name']}, request=self.context.get('request'))

    def validate_name(self, value):
        if self.instance is not None and self.instance['name'] != value:
            for record in DNSRecordSerializer.filter(zone=self.instance['name']):
                raise serializers.ValidationError(
                    "cannot modify the name of a zone with records"
                )
        return value

    def validate(self, data):
        data = super(DNSZoneSerializer, self).validate(data)
        if (self.instance is None and
                self.context['request'].user is not None
                and not self.context['request'].user.is_superuser
            ):
            zones = DNSZoneSerializer.filter(type=data['type'])
            parent = {'name': '.'}
            for zone in zones:
                if data['name'].endswith("." + zone['name']):
                    if len(zone['name']) > len(parent['name']):
                        parent = zone
            allowed = set(
                parent.get('permissions', {}).get('write', [])
                + parent.get('permissions', {}).get('create', [])
            )
            groups = set(self.context['request'].user.groups.all().values_list('name', flat=True))
            if len(groups.intersection(allowed)) == 0:
                raise serializers.ValidationError("you do not have permissions to zone %s" % (parent['name']))
        return data


class DNSRecordSerializer(NeedsReviewMixin, BonkTriggerMixin, HistorySerializerMixin):
    id = serializers.CharField(required=False)
    name = serializers.CharField(required=True, validators=[validate_fqdn])
    zone = serializers.CharField(required=True)
    type = serializers.ChoiceField(choices=['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'CAA', 'ANAME'], required=True)
    ttl = serializers.IntegerField(required=False, validators=[validate_ttl])
    value = serializers.ListField(child=serializers.CharField())
    reference = serializers.CharField(required=False)
    permissions = PermissionsSerializer(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'dns_record'
        slug_field = 'name_type'
        indices = [
            'name',
            'zone',
            ('name_type', (r.row['name'], r.row['type'])),
            ('zone_name_type', (r.row['zone'], r.row['name'], r.row['type'])),
            ('value', {'multi': True}),
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]
        unique_together = [
            ('zone', 'name', 'type'),
        ]

    def create_link(self, instance):
        return reverse('bonk:record_detail', kwargs={
                'name': instance['name'],
                'type': instance['type'],
            }, request=self.context.get('request'))

    def needs_review(self, instance, data):
        if not hasattr(self, '_zone'):
            self._zone = DNSZoneSerializer(DNSZoneSerializer.get(name=data.get('zone', instance['zone'] if instance else None)))
        return self._zone.needs_review(self._zone.instance, {})

    def get_reviewers(self, instance, data):
        reviewers = self._zone.get_reviewers(self._zone.instance, {})
        if instance is not None:
            reviewers.extend(super(DNSRecordSerializer, self).get_reviewers(instance, data))
        return reviewers

    def validate_zone(self, value):
        try:
            self._zone = DNSZoneSerializer(DNSZoneSerializer.get(name=value))
        except RethinkObjectNotFound:
            raise serializers.ValidationError("'%s' does not exist" % value)
        if 'request' in self.context and not self.context['request'].user.is_superuser:
            user_groups = set(self.context['request'].user.groups.all().values_list('name', flat=True))
            if self.instance is not None and len(user_groups.intersection(set(
                    self.instance.get('permissions', {}).get('write', [])
                ))) > 0:
                pass
            elif len(user_groups.intersection(set(
                    self._zone.instance.get('permissions', {}).get('create', [])
                    + self._zone.instance.get('permissions', {}).get('write', [])
                ))) == 0:
                raise serializers.ValidationError("you do not have permission to create names in %s" % value)
        return value

    def validate(self, data):
        data = super(DNSRecordSerializer, self).validate(data)
        full = self.get_updated_object(data)
        if full['name'] != full['zone'] and not full['name'].endswith('.' + full['zone']):
            raise serializers.ValidationError("name %s is not in zone %s" % (full['name'], full['zone']))
        if full['type'] == 'CNAME':
            records = list(DNSRecordSerializer.filter(name=full['name']))
            if self.instance is not None:
                records = [x for x in records if x['id'] != self.instance['id']]
            if len(records) > 0:
                raise serializers.ValidationError("a CNAME record cannot be used on a name with any other record type")
            if len(full['value']) > 1:
                raise serializers.ValidationError("a CNAME record can only have one value")
            addresses = list(IPAddressSerializer.filter(name=full['name']))
            if len(addresses) > 0:
                raise serializers.ValidationError("an address with the same name already exists")
        else:
            records = list(DNSRecordSerializer.filter(name=full['name'], type='CNAME'))
            if self.instance is not None:
                records = [x for x in records if x['id'] != self.instance['id']]
            if len(records) > 0:
                raise serializers.ValidationError("a CNAME record exists for the specified name already")
        try:
            dns.zone.from_text(
                "\n".join(["%s. %d IN %s %s" % (full['name'], full.get('ttl', 86400), full['type'].replace("ANAME", "CNAME"), v) for v in full['value']]),
                origin=full['zone'], check_origin=False
            )
        except dns.exception.SyntaxError:
            raise serializers.ValidationError("value is invalid")
        return data


class DHCPServerSetSerializer(BonkTriggerMixin, HistorySerializerMixin):
    id = serializers.CharField(required=False)
    name = serializers.CharField(required=True)
    servers = serializers.ListField(child=serializers.IPAddressField())

    class Meta(RethinkSerializer.Meta):
        table_name = 'dhcp_server_set'
        slug_field = 'name'
        indices = [
            'name',
        ]
        unique = [
            'name',
        ]

    def create_link(self, instance):
        return reverse('bonk:dhcp_server_set_detail', kwargs={'slug': instance['name']}, request=self.context.get('request'))
