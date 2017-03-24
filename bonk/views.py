import logging
import netaddr
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework import permissions
from socrates.rethink import RethinkAPIMixin
from bonk.serializers import *

logger = logging.getLogger("bonk.views")

class IsAdminForUpdate(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            return request.user.is_superuser
        else:
            return True

class VRFListView(RethinkAPIMixin, generics.ListCreateAPIView):
    pk_field = 'id'
    slug_field = 'vrf'
    serializer_class = VRFSerializer
    permission_classes = (permissions.IsAuthenticated, IsAdminForUpdate)

class VRFDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    pk_field = 'id'
    slug_field = 'vrf'
    serializer_class = VRFSerializer
    permission_classes = (permissions.IsAuthenticated, IsAdminForUpdate)

    def get_slug(self):
        return int(self.kwargs['vrf'])

class IsAllocatorPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        user_groups = set(request.user.groups.all().values_list('name', flat=True))
        return len(user_groups.intersection(set(obj['allocators']))) > 0

class IPBlockListView(RethinkAPIMixin, generics.ListCreateAPIView):
    pk_field = 'id'
    slug_field = 'vrf_network_length'
    serializer_class = IPBlockSerializer
    group_filter_fields = ['allocators']
    permission_classes = (permissions.IsAuthenticated, IsAdminForUpdate)

class IPBlockDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    pk_field = 'id'
    slug_field = 'vrf_network_length'
    serializer_class = IPBlockSerializer
    group_filter_fields = ['allocators']
    permission_classes = (permissions.IsAuthenticated, IsAllocatorPermission, IsAdminForUpdate)

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['network'], int(self.kwargs['length'])]

class IPBlockAllocateView(RethinkAPIMixin, generics.CreateAPIView):
    slug_field = 'vrf_network_length'
    serializer_class = IPBlockSerializer
    group_filter_fields = ['allocators']
    permission_classes = (permissions.IsAuthenticated, IsAllocatorPermission)

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['network'], int(self.kwargs['length'])]

    def create(self, *args, **kwargs):
        block = self.get_object()
        if 'hosts' in self.request.data and 'length' not in self.request.data:
            if isinstance(self.request.data['hosts'], int):
                s = bin(num_hosts + 2)[2:]
                length = ((32 - len(s)) * "0" + s).find("1")
            else:
                raise serializers.ValidationError("hosts is invalid")
        elif 'length' not in self.request.data:
            raise serializers.ValidationError("prefix length is required")
        elif (not isinstance(self.request.data['length'], int) or
              self.request.data['length'] < block['length'] or
              self.request.data['length'] > 30):
            raise serializers.ValidationError("prefix length is invalid")
        else:
            length = self.request.data['length']
        if 'managers' not in self.request.data:
            raise serializers.ValidationError("managers is required")
        pool = netaddr.IPSet([netaddr.IPNetwork("%s/%d" % (block['network'], block['length']))])
        used = netaddr.IPSet()
        for prefix in IPPrefixSerializer.filter_by_block(block):
            used.add(netaddr.IPNetwork("%s/%d" % (prefix['network'], prefix['length'])))
        available = pool ^ used
        larger = None
        for prefix in available.iter_cidrs():
            if prefix.prefixlen == length:
                break
            elif prefix.prefixlen < length and (larger is None or larger.prefixlen > prefix.prefixlen):
                larger = prefix
        else:
            if larger is None:
                raise serializers.ValidationError("IP block is exhausted")
            prefix = larger.subnet(length).next()
        obj = {
            'vrf': block['vrf'],
            'network': str(prefix.network),
            'length': prefix.prefixlen,
            'state': self.request.data.get('state', 'allocated'),
            'managers': self.request.data['managers'],
        }
        serializer = IPPrefixSerializer(None, data=obj, context={'request': self.request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.save(), status=status.HTTP_201_CREATED)

class IsManagerPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        user_groups = set(request.user.groups.all().values_list('name', flat=True))
        return len(user_groups.intersection(set(obj['managers']))) > 0

class IPPrefixListView(RethinkAPIMixin, generics.ListCreateAPIView):
    pk_field = 'id'
    slug_field = 'vrf_network_length'
    serializer_class = IPPrefixSerializer
    group_filter_fields = ['managers']
    permission_classes = (permissions.IsAuthenticated,)

class IPPrefixDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    pk_field = 'id'
    slug_field = 'vrf_network_length'
    serializer_class = IPPrefixSerializer
    group_filter_fields = ['managers']
    permission_classes = (permissions.IsAuthenticated, IsManagerPermission)

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['network'], int(self.kwargs['length'])]

class IPPrefixAllocateView(RethinkAPIMixin, generics.CreateAPIView):
    slug_field = 'vrf_network_length'
    serializer_class = IPPrefixSerializer
    group_filter_fields = ['managers']
    permission_classes = (permissions.IsAuthenticated, IsManagerPermission)

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['network'], int(self.kwargs['length'])]

    def create(self, *args, **kwargs):
        prefix = self.get_object()
        if 'name' not in self.request.data:
            raise serializers.ValidationError("name is required")
        network = netaddr.IPNetwork("%s/%d" % (prefix['network'], prefix['length']))
        used = netaddr.IPSet()
        for address in IPAddressSerializer.filter_by_prefix(prefix):
            used.add(netaddr.IPAddress(address['ip']))
        available = netaddr.IPSet(network) ^ used
        if 'ip' not in self.request.data:
            for address in available:
                if address not in (network.network, network.broadcast):
                    break
            else:
                raise serializers.ValidationError("network is exhausted")
        else:
            address = netaddr.IPAddress(self.request.data['ip'])
            if address not in available:
                raise serializers.ValidationError("ip='%s' is already in use" % self.request.data['ip'])
        obj = {
            'state': self.request.data.get('state', 'allocated'),
            'vrf': prefix['vrf'],
            'ip': str(address),
            'name': self.request.data['name'],
        }
        serializer = IPAddressSerializer(None, data=obj, context={'request': self.request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.save(), status=status.HTTP_201_CREATED)

class IsPrefixManagerPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        user_groups = set(request.user.groups.all().values_list('name', flat=True))
        ip = netaddr.IPAddress(obj['ip']).value
        prefix = r.table("ip_prefix").filter(lambda prefix:
                    r.js("(" + str(ip) + " & ~(Math.pow(2, 32 - " +
                        prefix['length'].coerce_to("string") + ") - 1)) == " +
                        r.map(
                            prefix['network'].split(".").map(lambda octet: octet.coerce_to("number")),
                            [1 << 24, 1 << 16, 1 << 8, 1], lambda octet, multiplier: octet * multiplier).
                        sum().coerce_to("string")
                    )
                ).order_by(r.desc("length")).nth(0).run(request.get_connection())
        return len(user_groups.intersection(set(prefix['managers']))) > 0

class IPAddressListView(RethinkAPIMixin, generics.ListCreateAPIView):
    pk_field = 'id'
    slug_field = 'vrf_ip'
    serializer_class = IPAddressSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def default_filter_queryset(self, queryset):
        if self.request.user.is_superuser:
            return queryset
        queryset = queryset. \
            merge(lambda address: {"prefix":
                r.table("ip_prefix").filter(lambda prefix:
                    r.js("(" +
                        r.map(
                            address['ip'].split(".").map(lambda octet: octet.coerce_to("number")),
                            [1 << 24, 1 << 16, 1 << 8, 1], lambda octet, multiplier: octet * multiplier).
                        sum().coerce_to("string") +
                        " & ~(Math.pow(2, 32 - " +
                        prefix['length'].coerce_to("string") + ") - 1)) == " +
                        r.map(
                            prefix['network'].split(".").map(lambda octet: octet.coerce_to("number")),
                            [1 << 24, 1 << 16, 1 << 8, 1], lambda octet, multiplier: octet * multiplier).
                        sum().coerce_to("string")
                    )
                ).order_by(r.desc("length")).nth(0)})
        groups = self.request.user.groups.all().values_list('name', flat=True)
        queryset = queryset.filter(lambda address: address['prefix']['managers'].set_intersection(groups).count() > 0)
        return queryset

class IPAddressDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    pk_field = 'id'
    slug_field = 'vrf_ip'
    serializer_class = IPAddressSerializer
    permission_classes = (permissions.IsAuthenticated, IsPrefixManagerPermission)

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['address']]
