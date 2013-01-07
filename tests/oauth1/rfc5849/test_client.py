# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from oauthlib.oauth1.rfc5849 import Client, bytes_type
from ...unittest import TestCase


class ClientRealmTests(TestCase):

    def test_client_no_realm(self):
        client = Client("client-key")
        uri, header, body = client.sign("example-uri")
        self.assertTrue(
            header["Authorization"].startswith('OAuth oauth_nonce='))

    def test_client_realm_sign_with_default_realm(self):
        client = Client("client-key", realm="moo-realm")
        self.assertEqual(client.realm, "moo-realm")
        uri, header, body = client.sign("example-uri")
        self.assertTrue(
            header["Authorization"].startswith('OAuth realm="moo-realm",'))

    def test_client_realm_sign_with_additional_realm(self):
        client = Client("client-key", realm="moo-realm")
        uri, header, body = client.sign("example-uri", realm="baa-realm")
        self.assertTrue(
            header["Authorization"].startswith('OAuth realm="baa-realm",'))
        # make sure sign() does not override the default realm
        self.assertEqual(client.realm, "moo-realm")


class ClientConstructorTests(TestCase):

    def test_convert_to_unicode_resource_owner(self):
        client = Client('client-key',
                        resource_owner_key=b'owner key')
        self.assertFalse(isinstance(client.resource_owner_key, bytes_type))
        self.assertEqual(client.resource_owner_key, 'owner key')

    def test_give_explicit_timestamp(self):
        client = Client('client-key', timestamp='1')
        params = dict(client.get_oauth_params())
        self.assertEqual(params['oauth_timestamp'], '1')

    def test_give_explicit_nonce(self):
        client = Client('client-key', nonce='1')
        params = dict(client.get_oauth_params())
        self.assertEqual(params['oauth_nonce'], '1')
