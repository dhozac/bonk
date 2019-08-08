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
from django.conf.urls import include, url
from bonk.views import *

app_name = 'bonk'
urlpatterns = [
    url(r'^vrf/?$', VRFListView.as_view(), name='vrf_list'),
    url(r'^vrf/(?P<vrf>[0-9]+)/?$', VRFListView.as_view(), name='vrf_detail'),
    url(r'^block/?$', IPBlockListView.as_view(), name='block_list'),
    url(r'^block/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/?$', IPBlockDetailView.as_view(), name='block_detail'),
    url(r'^block/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/allocate/?$', IPBlockAllocateView.as_view(), name='block_allocate'),
    url(r'^prefix/?$', IPPrefixListView.as_view(), name='prefix_list'),
    url(r'^prefix/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/?$', IPPrefixDetailView.as_view(), name='prefix_detail'),
    url(r'^prefix/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/allocate/?$', IPPrefixAllocateView.as_view(), name='prefix_allocate'),
    url(r'^address/?$', IPAddressListView.as_view(), name='address_list'),
    url(r'^address/(?P<vrf>[0-9]+)/(?P<ip>[0-9a-f.:]+)/?$', IPAddressDetailView.as_view(), name='address_detail'),
    url(r'^zone/?$', DNSZoneListView.as_view(), name='zone_list'),
    url(r'^zone/(?P<slug>[A-Za-z0-9-.]+)/?$', DNSZoneDetailView.as_view(), name='zone_detail'),
    url(r'^record/?$', DNSRecordListView.as_view(), name='record_list'),
    url(r'^record/(?P<name>[A-Za-z0-9-._*]+)/(?P<type>[A-Z]+)/?$', DNSRecordDetailView.as_view(), name='record_detail'),
    url(r'^dhcpserverset/?$', DHCPServerSetListView.as_view(), name='dhcp_server_set_list'),
    url(r'^dhcpserverset/(?P<slug>[A-Za-z0-9-._]+)/?$', DHCPServerSetDetailView.as_view(), name='dhcp_server_set_detail'),
]
