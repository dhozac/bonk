from django.conf.urls import include, url
from bonk.views import *

urlpatterns = [
    url(r'^vrf/?$', VRFListView.as_view(), name='vrf_list'),
    url(r'^vrf/(?P<vrf>[0-9]+)/?$', VRFListView.as_view(), name='vrf_detail'),
    url(r'^block/?$', IPBlockListView.as_view(), name='block_list'),
    url(r'^block/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/?$', IPBlockDetailView.as_view(), name='block_detail'),
    #url(r'^block/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/allocate/?$', IPBlockAllocateView.as_view(), name='block_allocate'),
    url(r'^prefix/?$', IPPrefixListView.as_view(), name='prefix_list'),
    url(r'^prefix/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/?$', IPPrefixDetailView.as_view(), name='prefix_detail'),
    #url(r'^prefix/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/allocate/?$', IPPrefixAllocateView.as_view(), name='prefix_allocate'),
    url(r'^address/?$', IPAddressListView.as_view(), name='address_list'),
    url(r'^address/(?P<vrf>[0-9]+)/(?P<ip>[0-9a-f.:]+)/?$', IPAddressDetailView.as_view(), name='address_detail'),
]
