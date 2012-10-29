# -*- coding: utf-8 -*-
from __future__ import absolute_import

from oauthlib.oauth1.rfc5849 import Client
from ...unittest import TestCase


class ClientRealmTests(TestCase):

    def test_client_no_realm(self):
        client = Client(u"client-key")
        uri, header, body = client.sign(u"example-uri")
        self.assertTrue(
            header["Authorization"].startswith('OAuth oauth_nonce='))

    def test_client_realm_sign_with_default_realm(self):
        client = Client(u"client-key", realm=u"moo-realm")
        self.assertEqual(client.realm, u"moo-realm")
        uri, header, body = client.sign(u"example-uri")
        self.assertTrue(
            header["Authorization"].startswith('OAuth realm="moo-realm",'))

    def test_client_realm_sign_with_additional_realm(self):
        client = Client(u"client-key", realm=u"moo-realm")
        uri, header, body = client.sign(u"example-uri", realm=u"baa-realm")
        self.assertTrue(
            header["Authorization"].startswith('OAuth realm="baa-realm",'))

