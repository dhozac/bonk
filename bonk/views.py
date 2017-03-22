import logging
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
    group_filter_fields = []
    permission_classes = (permissions.IsAuthenticated, IsAdminForUpdate)

    def get_slug(self):
        return int(self.kwargs['vrf'])

class VRFDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    pk_field = 'id'
    slug_field = 'vrf'
    serializer_class = VRFSerializer
    group_filter_fields = []
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

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['network'], int(self.kwargs['length'])]

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

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['network'], int(self.kwargs['length'])]

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
        return len(user_groups.intersection(set(obj['managers']))) > 0

class IPAddressListView(RethinkAPIMixin, generics.ListCreateAPIView):
    pk_field = 'id'
    slug_field = 'vrf_ip'
    serializer_class = IPAddressSerializer
    group_filter_fields = []
    permission_classes = (permissions.IsAuthenticated,)

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['address']]

class IPAddressDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    pk_field = 'id'
    slug_field = 'vrf_ip'
    serializer_class = IPAddressSerializer
    group_filter_fields = []
    permission_classes = (permissions.IsAuthenticated, IsPrefixManagerPermission)

    def get_slug(self):
        return [int(self.kwargs['vrf']), self.kwargs['address']]
