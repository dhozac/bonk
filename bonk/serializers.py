from django.conf import settings
from django.contrib.auth.models import Group
from rest_framework import serializers
import netaddr
from socrates.rethink import r, BadRequestException, RethinkSerializer, RethinkObjectNotFound, RethinkMultipleObjectsFound, validate_unique_key

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

class VRFSerializer(RethinkSerializer):
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

class IPBlockSerializer(RethinkSerializer):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True)
    network = serializers.IPAddressField(required=True)
    length = serializers.IntegerField(required=True)
    announced_by = serializers.CharField(required=False)
    allocators = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False)

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

class IPPrefixSerializer(RethinkSerializer):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True)
    network = serializers.IPAddressField(required=True)
    length = serializers.IntegerField(required=True)
    asn = serializers.IntegerField(required=True)
    state = serializers.ChoiceField(required=True, choices=['allocated', 'reserved', 'quarantine'])
    managers = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False)
    dhcp = IPPrefixDHCPSerializer(required=False)
    ddns = IPPrefixDDNSSerializer(required=False)

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

class IPAddressSerializer(RethinkSerializer):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    vrf = serializers.IntegerField(required=True)
    ip = serializers.IPAddressField(required=True)
    name = serializers.CharField(required=True)
    dhcp_mac = serializers.CharField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'ip_address'
        slug_field = 'vrf_ip'
        indices = [
            'ip',
            'name',
            ('vrf_ip', (r.row['vrf'], r.row['ip'])),
        ]
        unique = [
            'name',
            'dhcp_mac',
        ]
        unique_together = [
            ('vrf', 'ip'),
        ]

class DNSZoneSerializer(RethinkSerializer):
    id = serializers.CharField(required=False, read_only=True)
    tags = serializers.DictField(required=False)
    needs_review = serializers.BooleanField(required=False, default=False)
    managers = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False)
    type = serializers.ChoiceField(required=True, choices=['internal', 'external'])
    ddns = DDNSSerializer(required=False)
    name = serializers.CharField(required=True)

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

class DNSRecordSerializer(RethinkSerializer):
    name = serializers.CharField(required=True)
    zone = serializers.CharField(required=True) # FOREIGN KEY TO DNSZone.name
    type = serializers.ChoiceField(choices=['A', 'AAAA', 'SRV', 'TXT'], required=True)
    ttl = serializers.IntegerField(required=False)
    value = serializers.ListField(child=serializers.CharField())

    class Meta(RethinkSerializer.Meta):
        table_name = 'dns_record'
        slug_field = 'name'
        indices = [
            'name',
            'zone',
            ('value', {'multi': True}),
        ]
        unique_together = [
            ('name', 'type'),
        ]

    def validate_zone(self, zone):
        try:
            DNSZoneSerializer.get(name=zone)
        except RethinkObjectNotFound:
            raise serializers.ValidationError("'%s' does not exist" % zone)
        return zone

    def validate(self, data):
        return data
