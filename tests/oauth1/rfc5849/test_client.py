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

    def test_decoding(self):
        client = Client('client_key', decoding='utf-8')
        uri, headers, body = client.sign('http://a.b/path?query',
                http_method='POST', body='a=b',
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertIsInstance(uri, bytes_type)
        self.assertIsInstance(body, bytes_type)
        for k, v in headers.items():
            self.assertIsInstance(k, bytes_type)
            self.assertIsInstance(v, bytes_type)


class SigningTest(TestCase):

    def test_case_insensitive_headers(self):
        client = Client('client_key')
        # Uppercase
        _, h, _ = client.sign('http://i.b/path', http_method='POST', body='',
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(h['Content-Type'], 'application/x-www-form-urlencoded')

        # Lowercase
        _, h, _ = client.sign('http://i.b/path', http_method='POST', body='',
                headers={'content-type': 'application/x-www-form-urlencoded'})
        self.assertEqual(h['content-type'], 'application/x-www-form-urlencoded')

        # Capitalized
        _, h, _ = client.sign('http://i.b/path', http_method='POST', body='',
                headers={'Content-type': 'application/x-www-form-urlencoded'})
        self.assertEqual(h['Content-type'], 'application/x-www-form-urlencoded')

        # Random
        _, h, _ = client.sign('http://i.b/path', http_method='POST', body='',
                headers={'conTent-tYpe': 'application/x-www-form-urlencoded'})
        self.assertEqual(h['conTent-tYpe'], 'application/x-www-form-urlencoded')

    def test_sign_no_body(self):
        client = Client('client_key', decoding='utf-8')
        self.assertRaises(ValueError, client.sign, 'http://i.b/path',
                http_method='POST', body=None,
                headers={'Content-Type': 'application/x-www-form-urlencoded'})

    def test_sign_empty_body(self):
        client = Client('client_key')
        _, h, b = client.sign('http://i.b/path', http_method='POST', body='',
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(h['Content-Type'], 'application/x-www-form-urlencoded')

    def test_sign_get_with_body(self):
        client = Client('client_key')
        for method in ('GET', 'HEAD'):
            self.assertRaises(ValueError, client.sign, 'http://a.b/path?query',
                    http_method=method, body='a=b',
                    headers={
                        'Content-Type': 'application/x-www-form-urlencoded'
                    })

    def test_sign_unicode(self):
        client = Client('client_key', nonce='abc', timestamp='abc')
        _, h, b = client.sign('http://i.b/path', http_method='POST',
                body='status=%E5%95%A6%E5%95%A6',
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(b, 'status=%E5%95%A6%E5%95%A6')
        self.assertIn('oauth_signature="yrtSqp88m%2Fc5UDaucI8BXK4oEtk%3D"', h['Authorization'])
        _, h, b = client.sign('http://i.b/path', http_method='POST',
                body='status=%C3%A6%C3%A5%C3%B8',
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(b, 'status=%C3%A6%C3%A5%C3%B8')
        self.assertIn('oauth_signature="oG5t3Eg%2FXO5FfQgUUlTtUeeZzvk%3D"', h['Authorization'])
