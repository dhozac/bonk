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
import base64
import json
import os
import netaddr
from django.test import TestCase, override_settings
from django.conf import settings
from django.core import management
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.hashers import make_password
import rethinkdb as r

from bonk.serializers import *

@override_settings(
    RETHINK_DB_DB=os.environ.get('RETHINK_DB_DB', 'bonkci'),
)
class APITests(TestCase):
    @classmethod
    def setUpClass(cls):
        super(APITests, cls).setUpClass()
        cls.conn = r.connect(host=settings.RETHINK_DB_HOST, port=settings.RETHINK_DB_PORT)
        try:
            r.db_drop(settings.RETHINK_DB_DB).run(cls.conn)
        except:
            pass
        r.db_create(settings.RETHINK_DB_DB).run(cls.conn)
        cls.conn.db = settings.RETHINK_DB_DB
        management.call_command('syncrethinkdb', verbosity=0)

    @classmethod
    def tearDownClass(cls):
        r.db_drop(settings.RETHINK_DB_DB).run(cls.conn)
        super(APITests, cls).tearDownClass()

    def tearDown(self):
        for t in ["vrf", "ip_prefix", "ip_block", "ip_address", "dns_zone", "dns_record", "dhcp_server_set"]:
            r.table(t).delete().run(self.conn)
        super(APITests, self).tearDown()

    def create_user(self, username='tester', password='tester', is_superuser=True, groups=[], **kwargs):
        user = get_user_model().objects.create(
            username=username,
            password=make_password(password),
            is_superuser=is_superuser,
            **kwargs
        )
        for name in groups:
            group, created = Group.objects.get_or_create(name=name)
            user.groups.add(group)
        auth = "Basic %s" % (base64.b64encode(("%s:%s" % (username, password)).encode("ascii")).decode("ascii"))
        return auth

    def create_common_objects(self):
        auth = self.create_user()
        response = self.client.post(reverse('bonk:vrf_list'), data=json.dumps({
            'vrf': 0, 'name': 'default'
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        return auth

    def create_ip_block(self, auth, vrf, network, length, name, **fields):
        response = self.client.post(reverse('bonk:block_list'), data=json.dumps(dict(fields,
            vrf=vrf,
            name=name,
            network=network,
            length=length,
        )), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def create_ip_prefix(self, auth, vrf, network, length, name, **fields):
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps(dict(fields,
            vrf=vrf,
            network=network,
            length=length,
            name=name,
            state=fields.get('state', 'allocated'),
        )), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def create_ip_address(self, auth, vrf, ip, name, **fields):
        response = self.client.post(reverse('bonk:address_list'), data=json.dumps(dict(fields,
            vrf=vrf,
            ip=ip,
            name=name,
            state=fields.get('state', 'allocated'),
        )), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def _create_zone(self, auth, name, **fields):
        return self.client.post(reverse('bonk:zone_list'), data=json.dumps(dict(fields,
            name=name,
            type=fields.get('type', 'internal'),
        )), content_type="application/json", HTTP_AUTHORIZATION=auth)

    def create_zone(self, auth, name, **fields):
        response = self._create_zone(auth, name, **fields)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def _create_record(self, auth, name, zone, type, value, **fields):
        return self.client.post(reverse('bonk:record_list'), data=json.dumps(dict(fields,
            name=name,
            zone=zone,
            type=type,
            value=value,
        )), content_type="application/json", HTTP_AUTHORIZATION=auth)

    def create_record(self, *args, **fields):
        response = self._create_record(*args, **fields)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def _allocate_ip_prefix(self, auth, vrf, block_network, block_length, **fields):
        return self.client.post(reverse('bonk:block_allocate', kwargs={
                    'vrf': vrf,
                    'network': block_network,
                    'length': block_length,
                }), data=json.dumps(dict(fields,
                    state=fields.get('state', 'allocated'),
                )), content_type="application/json", HTTP_AUTHORIZATION=auth)

    def allocate_ip_prefix(self, *args, **fields):
        response = self._allocate_ip_prefix(*args, **fields)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def _allocate_ip_address(self, auth, vrf, prefix_network, prefix_length, name, **fields):
        return self.client.post(reverse('bonk:prefix_allocate', kwargs={
                    'vrf': vrf,
                    'network': prefix_network,
                    'length': prefix_length
                }), data=json.dumps(dict(fields,
                    name=name,
                    state=fields.get('state', 'allocated'),
                )), content_type="application/json", HTTP_AUTHORIZATION=auth)

    def allocate_ip_address(self, *args, **fields):
        response = self._allocate_ip_address(*args, **fields)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def test_ip_block_get_by_ip(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1')
        self.assertEqual(IPBlockSerializer.get_by_ip(0, '10.0.0.0')['id'], ip_block['id'])
        self.assertEqual(IPBlockSerializer.get_by_ip(0, '10.0.255.255')['id'], ip_block['id'])
        with self.assertRaises(RethinkObjectNotFound):
            IPBlockSerializer.get_by_ip(0, '10.1.0.0')

    def test_ip_block_invalid_vrf(self):
        auth = self.create_common_objects()
        response = self.client.post(reverse('bonk:block_list'), data=json.dumps({
            'vrf': 1,
            'network': '10.0.0.0',
            'length': 16,
            'name': 'block1'
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('vrf', json.loads(response.content))

    def test_ip_block_invalid_network(self):
        auth = self.create_common_objects()
        response = self.client.post(reverse('bonk:block_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.1.0',
            'length': 16,
            'name': 'block1'
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_invalid_vrf(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1')
        response = self._allocate_ip_prefix(auth, 1, '10.0.0.0', 16, length=24, name='prefix1', permissions={})
        self.assertEqual(response.status_code, 404)

    def test_ip_prefix_get_by_ip(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1')
        ip_prefix = self.create_ip_prefix(auth, 0, '10.0.1.0', 24, 'prefix1')
        self.assertEqual(IPPrefixSerializer.get_by_ip(0, '10.0.1.0')['id'], ip_prefix['id'])
        self.assertEqual(IPPrefixSerializer.get_by_ip(0, '10.0.1.255')['id'], ip_prefix['id'])
        with self.assertRaises(RethinkObjectNotFound):
            IPPrefixSerializer.get_by_ip(0, '10.0.0.0')
        with self.assertRaises(RethinkObjectNotFound):
            IPPrefixSerializer.get_by_ip(0, '10.0.2.0')

    def test_ip_prefix_list_as_user(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        user2_auth = self.create_user('user2', is_superuser=False, groups=['group2'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1', 'group2']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        ip_prefix2 = self.allocate_ip_prefix(user2_auth, 0, '10.0.0.0', 16, length=24, name='prefix2', permissions={'write': ['group2']})

        response = self.client.get(reverse('bonk:prefix_list'), HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], ip_prefix1['id'])

        response = self.client.get(reverse('bonk:prefix_list'), HTTP_AUTHORIZATION=user2_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], ip_prefix2['id'])

    def test_ip_prefix_allocate_forbidden(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={})
        response = self._allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        self.assertEqual(response.status_code, 403)

    def test_ip_prefix_allocate_hosts(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, hosts=13, name='prefix1', permissions={'write': ['group1']})
        self.assertEqual(ip_prefix1['length'], 28)

    def test_ip_prefix_allocate_nothing(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        response = self._allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, name='prefix1', permissions={'write': ['group1']})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'length', response.content)

    def test_ip_prefix_allocate_exhaustive(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=17, name='prefix1', permissions={'write': ['group1']})
        ip_prefix2 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=17, name='prefix2', permissions={'write': ['group1']})
        response = self._allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=17, name='prefix3', permissions={'write': ['group1']})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'exhausted', response.content)

    def test_ip_prefix_allocate_no_permissions(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        response = self._allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=17, name='prefix1')
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'permissions', response.content)

    def test_ip_prefix_no_block(self):
        auth = self.create_common_objects()
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.0',
            'length': 24,
            'state': 'allocated',
            'name': 'prefix1',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_larger_than_block(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={})
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.0',
            'length': 8,
            'state': 'allocated',
            'name': 'prefix1',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_overlap(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', allocators=[])
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.0',
            'length': 24,
            'state': 'allocated',
            'name': 'prefix1',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.128',
            'length': 28,
            'state': 'allocated',
            'name': 'prefix2',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_underlap(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', allocators=[])
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.128',
            'length': 28,
            'state': 'allocated',
            'name': 'prefix1',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.0',
            'length': 24,
            'state': 'allocated',
            'name': 'prefix2',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_invalid_network(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', allocators=[])
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.128',
            'length': 24,
            'state': 'allocated',
            'name': 'prefix1',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_high_ip(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '128.0.0.0', 24, 'block1')
        ip_prefix1 = self.allocate_ip_prefix(auth, 0, '128.0.0.0', 24, length=28, name='prefix1', permissions={})

    def test_ip_prefix_delete_addresses(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1')
        ip_prefix = self.allocate_ip_prefix(auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={})
        zone = self.create_zone(auth, 'my.zone')
        ip1 = self.allocate_ip_address(auth, 0, ip_prefix['network'], ip_prefix['length'], 'test1.my.zone', permissions={})
        response = self.client.delete(reverse('bonk:prefix_detail', kwargs={
                'vrf': ip_prefix['vrf'], 'network': ip_prefix['network'], 'length': ip_prefix['length']
            }), HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 204)
        response = self.client.get(reverse('bonk:address_list'), HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 0)

    def test_create_prefix_without_permission(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={})
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.1.0',
            'length': 24,
            'state': 'allocated',
            'name': 'prefix1',
        }), content_type="application/json", HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('non_field_errors', data)
        self.assertIn('permission', data['non_field_errors'][0])

    def test_ip_address_allocate(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        user2_auth = self.create_user('user2', is_superuser=False, groups=['group2'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1', 'group2']})
        zone = self.create_zone(auth, 'my.zone', permissions={'write': ['group1', 'group2']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        ip_prefix2 = self.allocate_ip_prefix(user2_auth, 0, '10.0.0.0', 16, length=24, name='prefix2', permissions={'write': ['group2']})

        ip1 = self.allocate_ip_address(user1_auth, 0, ip_prefix1['network'], ip_prefix1['length'], 'test1.my.zone')
        ip2 = self.allocate_ip_address(user2_auth, 0, ip_prefix2['network'], ip_prefix2['length'], 'test2.my.zone')
        self.assertIn(netaddr.IPAddress(ip1['ip']), netaddr.IPNetwork("%s/%d" % (ip_prefix1['network'], ip_prefix1['length'])))
        self.assertIn(netaddr.IPAddress(ip2['ip']), netaddr.IPNetwork("%s/%d" % (ip_prefix2['network'], ip_prefix2['length'])))

        response = self.client.get(reverse('bonk:address_list'), HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], ip1['id'])
        response = self.client.get(reverse('bonk:address_list'), HTTP_AUTHORIZATION=user2_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], ip2['id'])

    def test_ip_address_allocate_no_zone(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        response = self._allocate_ip_address(user1_auth, 0, ip_prefix1['network'], ip_prefix1['length'], 'test1.my.zone')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('name', data)
        self.assertIn('matching', data['name'][0])

    def test_ip_address_allocate_no_zone_permission(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        zone = self.create_zone(auth, 'my.zone', permissions={})
        response = self._allocate_ip_address(user1_auth, 0, ip_prefix1['network'], ip_prefix1['length'], 'test1.my.zone')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('name', data)
        self.assertIn('permission', data['name'][0])

    def test_ip_address_allocate_duplicate_name(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        zone = self.create_zone(auth, 'my.zone', permissions={'write': ['group1']})
        ip1 = self.allocate_ip_address(user1_auth, 0, ip_prefix1['network'], ip_prefix1['length'], 'test1.my.zone')
        response = self._allocate_ip_address(user1_auth, 0, ip_prefix1['network'], ip_prefix1['length'], 'test1.my.zone')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('name', data)
        self.assertIn('already', data['name'][0])

    def test_ip_address_create_no_prefix(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={})
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        zone = self.create_zone(auth, 'my.zone', permissions={'create': ['group1']})
        response = self.client.post(reverse('bonk:address_list'), data=json.dumps({
            'vrf': 0,
            'ip': '10.0.0.2',
            'name': 'test1.my.zone',
            'state': 'allocated',
        }), content_type="application/json", HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('non_field_errors', data)
        self.assertIn('no prefix found', data['non_field_errors'][0])

    def test_ip_address_allocate_no_name(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        zone = self.create_zone(auth, 'my.zone', permissions={'create': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        response = self.client.post(reverse('bonk:prefix_allocate', kwargs={
                'vrf': 0,
                'network': ip_prefix1['network'],
                'length': ip_prefix1['length']
            }), data=json.dumps({
                'vrf': 0,
                'ip': '10.0.0.2',
                'state': 'allocated',
            }), content_type="application/json", HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('name', data[0])

    def test_ip_address_allocate_exhaustive(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        zone = self.create_zone(auth, 'my.zone', permissions={'write': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=28, name='prefix1', permissions={'write': ['group1']})
        for i in range(0, 14):
            self.allocate_ip_address(user1_auth, ip_prefix1['vrf'], ip_prefix1['network'], ip_prefix1['length'], "ip%d.my.zone" % i)
        response = self._allocate_ip_address(user1_auth, ip_prefix1['vrf'], ip_prefix1['network'], ip_prefix1['length'], "ip-fail.my.zone")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'exhausted', response.content)

    def test_ip_address_allocate_specific(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        zone = self.create_zone(auth, 'my.zone', permissions={'write': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        self.allocate_ip_address(user1_auth, ip_prefix1['vrf'], ip_prefix1['network'], ip_prefix1['length'], "ip2.my.zone", ip='10.0.0.2')
        response = self._allocate_ip_address(user1_auth, ip_prefix1['vrf'], ip_prefix1['network'], ip_prefix1['length'], "ip2.my.zone", ip='10.0.0.2')
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'already in use', response.content)

    def test_ip_address_allocate_ttl(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        zone = self.create_zone(auth, 'my.zone', permissions={'write': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        response = self.client.post(reverse('bonk:prefix_allocate', kwargs={
                'vrf': 0,
                'network': ip_prefix1['network'],
                'length': ip_prefix1['length']
            }), data=json.dumps({
                'vrf': 0,
                'ip': '10.0.0.2',
                'name': 'test1.my.zone',
                'state': 'allocated',
                'ttl': 300,
            }), content_type="application/json", HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.content)
        self.assertEqual(data['ttl'], 300)

    def test_ip_address_detail(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        user2_auth = self.create_user('user2', is_superuser=False, groups=['group2'])
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, 'block1', permissions={'create': ['group1']})
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, length=24, name='prefix1', permissions={'write': ['group1']})
        zone = self.create_zone(auth, 'my.zone', permissions={'write': ['group1']})
        ip1 = self.allocate_ip_address(user1_auth, 0, ip_prefix1['network'], ip_prefix1['length'], 'test1.my.zone')
        for iter_auth, code in [(user2_auth, 403), (user1_auth, 200)]:
            response = self.client.patch(reverse('bonk:address_detail', kwargs={
                    'vrf': ip1['vrf'],
                    'ip': ip1['ip'],
                }), data=json.dumps({
                    'version': ip1['version'],
                    'dhcp_mac': ['de:ad:be:ef:00:01'],
                }), content_type="application/json", HTTP_AUTHORIZATION=iter_auth)
            self.assertEqual(response.status_code, code)

    def test_dns_zones_list(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        user2_auth = self.create_user('user2', is_superuser=False, groups=['group2'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        zone2 = self.create_zone(auth, 'my2.zone', permissions={'write': ['group2']})
        zone3 = self.create_zone(auth, 'my3.zone', permissions={'write': ['group1', 'group2']})

        response = self.client.get(reverse('bonk:zone_list'), HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 2)
        self.assertEqual(set(map(lambda x: x['id'], data)), set([zone1['id'], zone3['id']]))

        response = self.client.get(reverse('bonk:zone_list'), HTTP_AUTHORIZATION=user2_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 2)
        self.assertEqual(set(map(lambda x: x['id'], data)), set([zone2['id'], zone3['id']]))

    def test_dns_zone_create_without_permission(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        response = self._create_zone(user1_auth, 'my1.zone', permissions={'write': ['group1']})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('non_field_errors', data)
        self.assertIn('permission', data['non_field_errors'][0])

    def test_dns_zone_create_with_permission(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        root_zone = self.create_zone(auth, 'zone', permissions={'create': ['group1']})
        my_zone = self.create_zone(user1_auth, 'my1.zone', permissions={'write': ['group1']})

    def test_dns_zone_rename_without_records(self):
        auth = self.create_common_objects()
        zone = self.create_zone(auth, 'my1.zone')
        response = self.client.patch(
            reverse('bonk:zone_detail', kwargs={'slug': zone['name']}),
            data=json.dumps({
                'name': 'my2.zone',
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=auth
        )
        self.assertEqual(response.status_code, 200)

    def test_dns_zone_rename_with_records(self):
        auth = self.create_common_objects()
        zone = self.create_zone(auth, 'my1.zone')
        record_apex1 = self.create_record(auth, zone['name'], zone['name'], 'A', ['127.0.0.1'])
        response = self.client.patch(
            reverse('bonk:zone_detail', kwargs={'slug': zone['name']}),
            data=json.dumps({
                'name': 'my2.zone',
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=auth
        )
        self.assertEqual(response.status_code, 400)

    def test_dns_records_list(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        user2_auth = self.create_user('user2', is_superuser=False, groups=['group2'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        zone2 = self.create_zone(auth, 'my2.zone', permissions={'write': ['group2']})
        record_apex1 = self.create_record(user1_auth, 'my1.zone', 'my1.zone', 'A', ['127.0.0.1'])
        record_www1 = self.create_record(user1_auth, 'www.my1.zone', 'my1.zone', 'A', ['127.0.0.1'])
        record_apex2 = self.create_record(user2_auth, 'my2.zone', 'my2.zone', 'A', ['127.0.0.1'])
        record_www2 = self.create_record(user2_auth, 'www.my2.zone', 'my2.zone', 'A', ['127.0.0.1'])

        response = self.client.get(reverse('bonk:record_list'), HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 2)
        self.assertEqual(set(map(lambda x: x['id'], data)), set([record_apex1['id'], record_www1['id']]))

        response = self.client.get(reverse('bonk:record_list'), HTTP_AUTHORIZATION=user2_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 2)
        self.assertEqual(set(map(lambda x: x['id'], data)), set([record_apex2['id'], record_www2['id']]))

    def test_dns_records_no_zone(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        response = self._create_record(user1_auth, 'my1.zone', 'my1.zone', 'A', ['127.0.0.1'])
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('zone', data)

    def test_dns_records_no_manager(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        user2_auth = self.create_user('user2', is_superuser=False, groups=['group2'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        response = self._create_record(user2_auth, 'my1.zone', 'my1.zone', 'A', ['127.0.0.1'])
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('zone', data)

    def test_dns_records_name_not_in_zone(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        response = self._create_record(user1_auth, 'my2.zone', 'my1.zone', 'A', ['127.0.0.1'])
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('non_field_errors', data)

    def test_dns_records_cname_for_existing(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        self.create_record(user1_auth, 'service.my1.zone', 'my1.zone', 'A', ['127.0.0.1'])
        response = self._create_record(user1_auth, 'service.my1.zone', 'my1.zone', 'CNAME', ['service2.my2.zone'])
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('non_field_errors', data)

    def test_dns_records_a_for_cname(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        self.create_record(user1_auth, 'service.my1.zone', 'my1.zone', 'CNAME', ['service.my2.zone'])
        response = self._create_record(user1_auth, 'service.my1.zone', 'my1.zone', 'A', ['127.0.0.1'])
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('non_field_errors', data)

    def test_dns_records_invalid_a(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        response = self._create_record(user1_auth, 'service.my1.zone', 'my1.zone', 'A', ['service.my2.zone.'])
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn('non_field_errors', data)

    def test_dns_records_aname(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        self.create_record(user1_auth, 'service.my1.zone', 'my1.zone', 'ANAME', ['service.my2.zone'])

    def test_dns_record_detail(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1']})
        record = self.create_record(user1_auth, 'service.my1.zone', 'my1.zone', 'CNAME', ['service.my2.zone'])
        response = self.client.patch(reverse('bonk:record_detail', kwargs={
                'name': record['name'],
                'type': record['type'],
            }), data=json.dumps({
                'version': record['version'],
                'type': 'A',
                'value': ['127.0.0.1'],
            }), content_type="application/json", HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 200)

    def test_dns_records_reviews(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])
        user2_auth = self.create_user('user2', is_superuser=False, groups=['group2'])
        zone1 = self.create_zone(auth, 'my1.zone', permissions={'write': ['group1'], 'create': ['group2']}, needs_review=True)

        response = self._create_record(user2_auth, 'www.my1.zone', 'my1.zone', 'A', ['127.0.0.1'], permissions={'write': ['group2']})
        self.assertEqual(response.status_code, 202)
        data = json.loads(response.content)
        self.assertEqual(data[0], 'review created')

        response = self.client.patch(reverse('django_rethink:review_detail', kwargs={'id': data[1]}), data=json.dumps({
            'approvals': ['user1'],
        }), content_type="application/json", HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 200)

        response = self.client.patch(reverse('django_rethink:review_detail', kwargs={'id': data[1]}), data=json.dumps({
            'state': 'executed',
        }), content_type="application/json", HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('bonk:record_list'), HTTP_AUTHORIZATION=user2_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'www.my1.zone')

    def test_dhcp_server_set_list(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])

        response = self.client.post(reverse('bonk:dhcp_server_set_list'), data=json.dumps({
            'name': 'dhcp-set-1',
            'servers': ['10.0.0.2', '10.0.0.3'],
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)

        response = self.client.get(reverse('bonk:dhcp_server_set_list'), HTTP_AUTHORIZATION=user1_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)

        response = self.client.get(reverse('bonk:dhcp_server_set_list'), HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)

    def test_dhcp_server_set_detail(self):
        auth = self.create_common_objects()
        user1_auth = self.create_user('user1', is_superuser=False, groups=['group1'])

        response = self.client.post(reverse('bonk:dhcp_server_set_list'), data=json.dumps({
            'name': 'dhcp-set-1',
            'servers': ['10.0.0.2', '10.0.0.3'],
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)

        response = self.client.get(reverse('bonk:dhcp_server_set_detail', kwargs={'slug': 'dhcp-set-1'}), HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)
