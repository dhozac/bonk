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
