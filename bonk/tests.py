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

import base64
import json
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
    RETHINK_DB_DB='bonkci',
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
        management.call_command('createdb', verbosity=0)

    @classmethod
    def tearDownClass(cls):
        r.db_drop(settings.RETHINK_DB_DB).run(cls.conn)
        super(APITests, cls).tearDownClass()

    def tearDown(self):
        for t in ["vrf", "ip_prefix", "ip_block", "dns_zone"]:
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
        auth = "Basic %s" % (base64.b64encode("%s:%s" % (username, password)))
        return auth

    def create_common_objects(self):
        auth = self.create_user()
        response = self.client.post(reverse('bonk:vrf_list'), data=json.dumps({
            'vrf': 0, 'name': 'default'
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        return auth

    def create_ip_block(self, auth, vrf, network, length, **fields):
        response = self.client.post(reverse('bonk:block_list'), data=json.dumps(dict(fields,
            vrf=vrf,
            network=network,
            length=length,
        )), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def create_ip_prefix(self, auth, vrf, network, length, **fields):
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps(dict(fields,
            vrf=vrf,
            network=network,
            length=length,
            state=fields.get('state', 'allocated'),
        )), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def _allocate_ip_prefix(self, auth, vrf, block_network, block_length, length, **fields):
        return self.client.post(reverse('bonk:block_allocate', kwargs={
                    'vrf': vrf,
                    'network': block_network,
                    'length': block_length
                }), data=json.dumps(dict(fields,
                    length=length,
                state=fields.get('state', 'allocated'),
            )), content_type="application/json", HTTP_AUTHORIZATION=auth)

    def allocate_ip_prefix(self, *args, **fields):
        response = self._allocate_ip_prefix(*args, **fields)
        self.assertEqual(response.status_code, 201)
        return json.loads(response.content)

    def test_ip_block_get_by_ip(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16)
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
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('vrf', json.loads(response.content))

    def test_ip_block_invalid_network(self):
        auth = self.create_common_objects()
        response = self.client.post(reverse('bonk:block_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.1.0',
            'length': 16,
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_invalid_vrf(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16)
        response = self._allocate_ip_prefix(auth, 1, '10.0.0.0', 16, 24, managers=[])
        self.assertEqual(response.status_code, 404)

    def test_ip_prefix_get_by_ip(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16)
        ip_prefix = self.create_ip_prefix(auth, 0, '10.0.1.0', 24)
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
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, allocators=['group1', 'group2'])
        ip_prefix1 = self.allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, 24, managers=['group1'])
        ip_prefix2 = self.allocate_ip_prefix(user2_auth, 0, '10.0.0.0', 16, 24, managers=['group2'])

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
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, allocators=[])
        response = self._allocate_ip_prefix(user1_auth, 0, '10.0.0.0', 16, 24, managers=['group1'])
        self.assertEqual(response.status_code, 403)

    def test_ip_prefix_no_block(self):
        auth = self.create_common_objects()
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.0',
            'length': 24,
            'state': 'allocated',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_larger_than_block(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, allocators=[])
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.0',
            'length': 8,
            'state': 'allocated',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_overlap(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, allocators=[])
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.0',
            'length': 24,
            'state': 'allocated',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.128',
            'length': 28,
            'state': 'allocated',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_underlap(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, allocators=[])
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.128',
            'length': 28,
            'state': 'allocated',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 201)
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.0',
            'length': 24,
            'state': 'allocated',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))

    def test_ip_prefix_invalid_network(self):
        auth = self.create_common_objects()
        ip_block = self.create_ip_block(auth, 0, '10.0.0.0', 16, allocators=[])
        response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
            'vrf': 0,
            'network': '10.0.0.128',
            'length': 24,
            'state': 'allocated',
        }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn('non_field_errors', json.loads(response.content))
