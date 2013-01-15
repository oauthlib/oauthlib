# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import time
from oauthlib.common import safe_string_equals
from oauthlib.oauth1.rfc5849 import *
from ...unittest import TestCase


class ServerTests(TestCase):

    CLIENT_KEY = 'dpf43f3p2l4k3l03'
    CLIENT_SECRET = 'kd94hf93k423kf44'

    RESOURCE_OWNER_KEY = 'kkk9d7dh3k39sjv7'
    RESOURCE_OWNER_SECRET = 'just-a-string    asdasd'

    RSA_KEY = "-----BEGIN PRIVATE KEY-----\n MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMOZ519ZczgJiUPI\n J9Oac424LUvJw+HXqB2PqwFxdrcar+FDJihQbuHxGhz7bhhHADPG9KhNH45V5sDI\n /g4USqdd9wys8lAqxQAA9AxV2vXX+HK+id+WOZUfBM78OnzeOdvUzyxgmRean+ps\n A/U+PwsiToeGp0ywFkBCF7VJvd8pAgMBAAECgYBuQDWWHQlAsL9aIVuxfgFcBFAj\n w9pRVglAgFZXPek4VCaGxh6f4pZdbFTXuTDZJkwK4z3MD4yV4f1q9N+ed/mLVsZv\n XJb22jQmnNKhiz/thDWz9f97z+TTSocC85H0zdsUrmRKlxIR6+ys9hpBPe2HSKbJ\n zEcW1IKDkM0acJYm8QJBAP12rHp00IrIdrUsm9rO6dinLZpbGeVu2LFPM0Me7nYO\n Kc/GqrLHTSnm91BDbj9IgFrk45mEcSCCOUYutoKgPy8CQQDFjv9ZHd3BkCSbojG1\n RyRVyJQXfZHGMBabta5jjjTJlO7bMjELSfPsnZxoILjyf06qX/LoqsAXrV0Imf8n\n d/EnAkAcZSUheuC6C4cw+NRlCPUtrlzvg/E8wNRJ2OOXS2nPk/qfKlSJPsaoQRXH\n yiYZtNecVzQgSLQbvjsIX8dWjvlFAkAEuHwFhx8rZuRZC7EgYcjOe/J99TQshi2k\n Ht1B573/Kx3iAvsFCAlaGBIKsu14be5VR+GoCZx5dF0KvZNJQCZ1AkEAuYIpaPLf\n xyvKM8kDJ3uyJ2OHiuVlhMNe8g9GX3hHU4UWx3QdnaVm92mx84iuwRdaB1k6Yhk/\n 9jQrjQ0RmlMjpw==\n -----END PRIVATE KEY-----"

    PUB_RSA_KEY = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDmedfWXM4CYlDyCfTmnONuC1L\nycPh16gdj6sBcXa3Gq/hQyYoUG7h8Roc+24YRwAzxvSoTR+OVebAyP4OFEqnXfcM\nrPJQKsUAAPQMVdr11/hyvonfljmVHwTO/Dp83jnb1M8sYJkXmp/qbAP1Pj8LIk6H\nhqdMsBZAQhe1Sb3fKQIDAQAB\n-----END PUBLIC KEY-----"

    URLENCODED = {"Content-Type": "application/x-www-form-urlencoded"}

    class TestServer(Server):

        @property
        def client_key_length(self):
            return 16, 16

        @property
        def request_token_length(self):
            return 16, 16

        @property
        def access_token_length(self):
            return 16, 16

        @property
        def enforce_ssl(self):
            return False

        def get_client_secret(self, client_key):
            return ServerTests.CLIENT_SECRET

        def get_access_token_secret(self, client_key, access_token):
            return ServerTests.RESOURCE_OWNER_SECRET

        def get_request_token_secret(self, client_key, request_token):
            return ServerTests.RESOURCE_OWNER_SECRET

        def get_rsa_key(self, client_key):
            return ServerTests.PUB_RSA_KEY

        def validate_client_key(self, client_key):
            return ServerTests.CLIENT_KEY == client_key

        def validate_access_token(self, client_key, access_token):
            return (ServerTests.CLIENT_KEY == client_key and
                    ServerTests.RESOURCE_OWNER_KEY == access_token)

        def validate_request_token(self, client_key, request_token):
            return (ServerTests.CLIENT_KEY == client_key and
                    ServerTests.RESOURCE_OWNER_KEY == request_token)

        def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
            request_token=None, access_token=None):
            return True

        def validate_realm(self, client_key, realm, uri,
                request_token=None, access_token=None, required_realm=None):
            return True

        def validate_verifier(self, client_key, request_token, verifier):
            return True

        def validate_redirect_uri(self, client_key, redirect_uri):
            return redirect_uri.startswith('http://client.example.com/')

    class ClientServer(Server):
        clients = ['foo']
        nonces = [('foo', 'once', '1234567891', 'fez')]
        owners = { 'foo' : ['abcdefghijklmnopqrstuvxyz', 'fez'] }
        assigned_realms = { ('foo', 'abcdefghijklmnopqrstuvxyz') : 'photos' }
        verifiers = { ('foo', 'fez') : 'shibboleth' }

        @property
        def client_key_length(self):
            return 1, 30

        @property
        def request_token_length(self):
            return 1, 30

        @property
        def access_token_length(self):
            return 1, 30

        @property
        def nonce_length(self):
            return 2, 30

        @property
        def verifier_length(self):
            return 2, 30

        @property
        def realms(self):
            return ['photos']

        @property
        def timestamp_lifetime(self):
            # Disabled check to allow hardcoded verification signatures
            return 1000000000

        @property
        def dummy_client(self):
            return 'dummy'

        @property
        def dummy_request_token(self):
            return 'dumbo'

        @property
        def dummy_access_token(self):
            return 'dumbo'

        def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
            request_token=None, access_token=None):
            resource_owner_key = request_token if request_token else access_token
            return not (client_key, nonce, timestamp, resource_owner_key) in self.nonces

        def validate_client_key(self, client_key):
            return client_key in self.clients

        def validate_access_token(self, client_key, access_token):
            return (self.owners.get(client_key) and
                    access_token in self.owners.get(client_key))

        def validate_request_token(self, client_key, request_token):
            return (self.owners.get(client_key) and
                    request_token in self.owners.get(client_key))

        def validate_requested_realm(self, client_key, realm):
            return True

        def validate_realm(self, client_key, access_token, uri=None, required_realm=None):
            return (client_key, access_token) in self.assigned_realms

        def validate_verifier(self, client_key, request_token, verifier):
            return ((client_key, request_token) in self.verifiers and
                     safe_string_equals(verifier, self.verifiers.get(
                        (client_key, request_token))))

        def validate_redirect_uri(self, client_key, redirect_uri):
            return redirect_uri.startswith('http://client.example.com/')

        def get_client_secret(self, client_key):
            return 'super secret'

        def get_access_token_secret(self, client_key, access_token):
            return 'even more secret'

        def get_request_token_secret(self, client_key, request_token):
            return 'even more secret'

    def test_basic_server_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
        )

        d = Client(self.CLIENT_KEY,
            signature_method=SIGNATURE_RSA,
            rsa_key=self.RSA_KEY,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
        )

        s = self.TestServer()

        uri, headers, body = c.sign('http://server.example.com:80/init')
        self.assertTrue(s.verify_request(uri, body=body, headers=headers)[0])

        uri, headers, body = d.sign('http://server.example.com:80/init')
        self.assertTrue(s.verify_request(uri, body=body, headers=headers)[0])

    def test_server_callback_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
            callback_uri='http://client.example.com/callback'
        )

        uri, headers, body = c.sign('http://server.example.com:80/init')

        s = self.TestServer()
        self.assertTrue(s.verify_request(uri, body=body, headers=headers,
            require_callback=True)[0])

    def test_server_invalid_callback_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
            callback_uri='http://attacker.example.com/callback'
        )

        uri, headers, body = c.sign('http://server.example.com:80/init')

        s = self.TestServer()
        self.assertFalse(s.verify_request(uri, body=body, headers=headers,
            require_callback=True)[0])

    def test_not_implemented(self):
        s = Server()
        self.assertRaises(NotImplementedError, s.get_client_secret, None)
        self.assertRaises(NotImplementedError, s.get_request_token_secret, None, None)
        self.assertRaises(NotImplementedError, s.get_access_token_secret, None, None)
        self.assertRaises(NotImplementedError, lambda: s.dummy_client)
        self.assertRaises(NotImplementedError, lambda: s.dummy_request_token)
        self.assertRaises(NotImplementedError, lambda: s.dummy_access_token)
        self.assertRaises(NotImplementedError, s.get_rsa_key, None)
        self.assertRaises(NotImplementedError, s.validate_client_key, None)
        self.assertRaises(NotImplementedError, s.validate_access_token, None, None)
        self.assertRaises(NotImplementedError, s.validate_request_token, None, None)
        self.assertRaises(NotImplementedError, s.validate_timestamp_and_nonce,
            None, None, None)
        self.assertRaises(NotImplementedError, s.validate_redirect_uri, None, None)
        self.assertRaises(NotImplementedError, s.validate_realm, None, None, None, None)
        self.assertRaises(NotImplementedError, s.validate_requested_realm, None, None)
        self.assertRaises(NotImplementedError, s.validate_verifier, None, None, None)

    def test_enforce_ssl(self):
        """Ensure SSL is enforced by default."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, 'http://example.com')

    def test_multiple_source_params(self):
        """Check for duplicate params"""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/?oauth_signature_method=HMAC-SHA1',
            body='oauth_version=foo')
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/?oauth_signature_method=HMAC-SHA1',
            headers={'Authorization' : 'OAuth oauth_signature="foo"'})
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/?oauth_signature_method=HMAC-SHA1',
            body='oauth_version=foo',
            headers={'Authorization' : 'OAuth oauth_signature="foo"'})
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/',
            body='oauth_signature=foo',
            headers={'Authorization' : 'OAuth oauth_signature_method="foo"'})

    def test_duplicate_params(self):
        """Ensure params are only supplied once"""

        s = Server()
        self.assertRaises(ValueError, s.verify_request,
            'https://a.b/?oauth_version=a&oauth_version=b')
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/',
            body='oauth_version=a&oauth_version=b')

    def test_mandated_params(self):
        """Ensure all mandatory params are present."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/')
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/',
             body=('oauth_signature=a&oauth_consumer_key=b&oauth_nonce'))

    def test_oauth_version(self):
        """OAuth version must be 1.0 if present."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/',
             body=('oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   'oauth_timestamp=a&oauth_signature_method=RSA-SHA1&'
                   'oauth_version=2.0'),
             headers=self.URLENCODED)

    def test_oauth_timestamp(self):
        """Check for a valid UNIX timestamp."""
        s = Server()

        # Invalid timestamp length, must be 10
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/',
             body=('oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   'oauth_timestamp=123456789'),
             headers=self.URLENCODED)

        # Invalid timestamp age, must be younger than 10 minutes
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/',
             body=('oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   'oauth_timestamp=1234567890'),
             headers=self.URLENCODED)

        # Timestamp must be an integer
        self.assertRaises(ValueError, s.verify_request, 'https://a.b/',
             body=('oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   'oauth_timestamp=123456789a'),
             headers=self.URLENCODED)

    def test_signature_method_validation(self):
        """Ensure valid signature method is used."""

        body=('oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
              'oauth_version=1.0&oauth_signature_method=%s&'
              'oauth_timestamp=1234567890')

        uri = 'https://example.com/'

        class HMACServer(Server):

            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_HMAC,)

        s = HMACServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'RSA-SHA1', headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'PLAINTEXT', headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'shibboleth', headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=body % '', headers=self.URLENCODED)

        class RSAServer(Server):

            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_RSA,)

        s = RSAServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'HMAC-SHA1', headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'PLAINTEXT', headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'shibboleth', headers=self.URLENCODED)

        class PlainServer(Server):

            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_PLAINTEXT,)

        s = PlainServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'HMAC-SHA1', headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'RSA-SHA1', headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=body % 'shibboleth', headers=self.URLENCODED)

    def test_check_methods(self):
        """Ensure values are correctly formatted.

        Default setting is to only allow alphanumeric characters and a length
        between 20 and 30 characters.
        """

        ts = int(time.time())

        client=('oauth_signature=a&oauth_timestamp=%s&oauth_nonce=c&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&'
              'oauth_consumer_key=%s')

        owner=('oauth_signature=a&oauth_timestamp=%s&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              'oauth_token=%s')

        nonce=('oauth_signature=a&oauth_timestamp=%s&oauth_nonce=%s&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&'
              'oauth_consumer_key=abcdefghijklmnopqrstuvwxyz')

        realm=('oauth_signature=a&oauth_timestamp=%s&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&'
              'realm=%s')

        verifier=('oauth_signature=a&oauth_timestamp=%s&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&'
              'oauth_verifier=%s')

        noverifier=('oauth_signature=a&oauth_timestamp=%s&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&')

        uri = 'https://example.com/'
        s = Server()

        # Invalid characters
        invalid = (ts, '%C3%A5abcdefghijklmnopqrstuvwxyz')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % invalid, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % invalid, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % invalid, headers=self.URLENCODED, require_verifier=True)
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % invalid, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % invalid,
            require_verifier=True, headers=self.URLENCODED)

        # Too short
        short = (ts, 'abcdefghi')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % short, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % short, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % short, headers=self.URLENCODED, require_verifier=True)
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % short, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % short,
            require_verifier=True, headers=self.URLENCODED)

        # Too long
        loong = (ts, 'abcdefghijklmnopqrstuvwxyz123456789')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % loong, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % loong, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % loong, headers=self.URLENCODED, require_verifier=True)
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % loong, headers=self.URLENCODED)
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % loong,
            require_verifier=True, headers=self.URLENCODED)

        # By default no realms are allowed
        test = (ts, 'shibboleth')
        self.assertRaises(ValueError, s.verify_request, uri, body=realm % test,
            require_realm=True, headers=self.URLENCODED)

        # Missing required owner
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % (ts, ''), headers=self.URLENCODED)

        # Missing required verifier
        self.assertRaises(ValueError, s.verify_request, uri, body=noverifier % ts,
            require_verifier=True, headers=self.URLENCODED)

    def test_client_validation(self):
        uri = 'https://example.com/'
        client = ('oauth_signature=fmrXnTF4lO4o%2BD0%2FlZaJHP%2FXqEY%3D&'
              'oauth_timestamp=1234567890&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&'
              'oauth_consumer_key={0}')

        s = self.ClientServer()
        self.assertFalse(s.verify_request(uri, headers=self.URLENCODED, body=client.format('bar'))[0])
        self.assertFalse(s.verify_request(uri, headers=self.URLENCODED, body=client.format('bar'))[0])
        self.assertTrue(s.verify_request(uri, headers=self.URLENCODED, body=client.format('foo'))[0])

    def test_nonce_and_timestamp_validation(self):
        uri = 'https://example.com/'
        replay = ('oauth_signature=fmrXnTF4lO4o%2BD0%2FlZaJHP%2FXqEY%3D&'
              'oauth_timestamp=1234567891&'
              'oauth_nonce=once&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_token=fez&'
              'oauth_consumer_key=foo')

        s = self.ClientServer()
        self.assertFalse(s.verify_request(uri, headers=self.URLENCODED, body=replay)[0])

    def test_resource_owner_validation(self):
        uri = 'https://example.com/'

        invalid_owner = ('oauth_signature=B0FUgxzDNOPzol0gTTlXREelYrU%3D&'
              'oauth_timestamp=1234567890&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_token=invalid&'
              'oauth_consumer_key=foo')

        owner_optional = ('oauth_signature=GTmmjtDdyqhDYHL5dDWjVIDx%2BTo%3D&'
              'oauth_timestamp=1234567890&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_consumer_key=foo')

        s = self.ClientServer()
        self.assertFalse(s.verify_request(uri, headers=self.URLENCODED,
            body=invalid_owner)[0])
        self.assertTrue(s.verify_request(uri, headers=self.URLENCODED,
            body=owner_optional, require_resource_owner=False)[0])

    def test_signature_verification(self):
        uri = 'https://example.com/'
        short_sig = ('oauth_signature=fmrXnTF4lO4o%2BD0%2FlZaJHP%2FXqEY&'
              'oauth_timestamp=1234567890&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&'
              'oauth_consumer_key=foo')

        plain = ('oauth_signature=correctlengthbutthewrongcontent1111&'
              'oauth_timestamp=1234567890&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=PLAINTEXT&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&'
              'oauth_consumer_key=foo')

        s = self.ClientServer()
        self.assertFalse(s.verify_request(uri, headers=self.URLENCODED, body=short_sig)[0])
        self.assertFalse(s.verify_request(uri, headers=self.URLENCODED, body=plain)[0])

    def test_realm_validation(self):
        uri = 'https://example.com/'
        realm = ('oauth_signature=fmrXnTF4lO4o%2BD0%2FlZaJHP%2FXqEY%3D&'
              'oauth_timestamp=1234567890&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_token=abcdefghijklmnopqrstuvxyz&'
              'oauth_consumer_key=foo&realm=photos')

        s = self.ClientServer()
        self.assertTrue(s.verify_request(uri, headers=self.URLENCODED, body=realm)[0])

    def test_verifier_validation(self):
        uri = 'https://example.com/'
        verifier = ('oauth_signature=6AsWnRg%2BZnvfJOZKgaC5JKrF3Pk%3D&'
              'oauth_timestamp=1234567890&'
              'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              'oauth_token=fez&oauth_consumer_key=foo&'
              'oauth_verifier=shibboleth')

        s = self.ClientServer()
        self.assertTrue(s.verify_request(uri, body=verifier,
            headers=self.URLENCODED, require_verifier=True)[0])

    def test_timing_attack(self):
        """Ensure near constant time verification."""
        # TODO:
        pass
