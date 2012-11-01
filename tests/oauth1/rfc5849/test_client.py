# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals 

from oauthlib.oauth1.rfc5849 import Client
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
