# -*- coding: utf-8 -*-
from __future__ import absolute_import
import time
from oauthlib.common import safe_compare
from oauthlib.oauth1.rfc5849 import *
from ...unittest import TestCase


class ServerTests(TestCase):

    CLIENT_KEY = u'dpf43f3p2l4k3l03'
    CLIENT_SECRET = u'kd94hf93k423kf44'

    RESOURCE_OWNER_KEY = u'kkk9d7dh3k39sjv7'
    RESOURCE_OWNER_SECRET = u'just-a-string    asdasd'

    RSA_KEY = u"-----BEGIN PRIVATE KEY-----\n MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMOZ519ZczgJiUPI\n J9Oac424LUvJw+HXqB2PqwFxdrcar+FDJihQbuHxGhz7bhhHADPG9KhNH45V5sDI\n /g4USqdd9wys8lAqxQAA9AxV2vXX+HK+id+WOZUfBM78OnzeOdvUzyxgmRean+ps\n A/U+PwsiToeGp0ywFkBCF7VJvd8pAgMBAAECgYBuQDWWHQlAsL9aIVuxfgFcBFAj\n w9pRVglAgFZXPek4VCaGxh6f4pZdbFTXuTDZJkwK4z3MD4yV4f1q9N+ed/mLVsZv\n XJb22jQmnNKhiz/thDWz9f97z+TTSocC85H0zdsUrmRKlxIR6+ys9hpBPe2HSKbJ\n zEcW1IKDkM0acJYm8QJBAP12rHp00IrIdrUsm9rO6dinLZpbGeVu2LFPM0Me7nYO\n Kc/GqrLHTSnm91BDbj9IgFrk45mEcSCCOUYutoKgPy8CQQDFjv9ZHd3BkCSbojG1\n RyRVyJQXfZHGMBabta5jjjTJlO7bMjELSfPsnZxoILjyf06qX/LoqsAXrV0Imf8n\n d/EnAkAcZSUheuC6C4cw+NRlCPUtrlzvg/E8wNRJ2OOXS2nPk/qfKlSJPsaoQRXH\n yiYZtNecVzQgSLQbvjsIX8dWjvlFAkAEuHwFhx8rZuRZC7EgYcjOe/J99TQshi2k\n Ht1B573/Kx3iAvsFCAlaGBIKsu14be5VR+GoCZx5dF0KvZNJQCZ1AkEAuYIpaPLf\n xyvKM8kDJ3uyJ2OHiuVlhMNe8g9GX3hHU4UWx3QdnaVm92mx84iuwRdaB1k6Yhk/\n 9jQrjQ0RmlMjpw==\n -----END PRIVATE KEY-----"
  
    PUB_RSA_KEY = u"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDmedfWXM4CYlDyCfTmnONuC1L\nycPh16gdj6sBcXa3Gq/hQyYoUG7h8Roc+24YRwAzxvSoTR+OVebAyP4OFEqnXfcM\nrPJQKsUAAPQMVdr11/hyvonfljmVHwTO/Dp83jnb1M8sYJkXmp/qbAP1Pj8LIk6H\nhqdMsBZAQhe1Sb3fKQIDAQAB\n-----END PUBLIC KEY-----"

    class TestServer(Server):

        @property
        def client_key_length(self):
            return 16, 16

        @property
        def resource_owner_key_length(self):
            return 16, 16

        @property
        def enforce_ssl(self):
            return False

        def get_client_secret(self, client_key):
            return ServerTests.CLIENT_SECRET

        def get_resource_owner_secret(self, client_key, resource_owner_key):
            return ServerTests.RESOURCE_OWNER_SECRET

        def get_rsa_key(self, client_key):
            return ServerTests.PUB_RSA_KEY

        def validate_client_key(self, client_key):
            return ServerTests.CLIENT_KEY == client_key

        def validate_resource_owner_key(self, client_key, resource_owner_key):
            return (ServerTests.CLIENT_KEY == client_key and
                    ServerTests.RESOURCE_OWNER_KEY == resource_owner_key)

        def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
            resource_owner_key=None):
            return True

        def validate_realm(self, client_key, resource_owner_key, realm, uri):
            return True

        def validate_verifier(self, client_key, resource_owner_key, verifier):
            return True

        def validate_redirect_uri(self, client_key, redirect_uri):
            return True

    class ClientServer(Server):
        clients = [u'foo']
        nonces = [(u'foo', u'once', u'1234567891', u'fez')]
        owners = { u'foo' : [u'abcdefghijklmnopqrstuvxyz', u'fez'] }
        assigned_realms = { (u'foo', u'fez') : u'photos' }
        verifiers = { (u'foo', u'fez') : u'shibboleth' }

        @property
        def client_key_length(self):
            return 1, 30

        @property
        def resource_owner_key_length(self):
            return 1, 30

        @property
        def nonce_length(self):
            return 2, 30

        @property
        def verifier_length(self):
            return 2, 30

        @property
        def realms(self):
            return [u'photos']

        @property
        def timestamp_lifetime(self):
            # Disabled check to allow hardcoded verification signatures
            return 1000000000

        @property
        def dummy_client(self):
            return u'dummy'

        @property
        def dummy_resource_owner(self):
            return u'dumbo'

        def validate_timestamp_and_nonce(self, client_key, timestamp, 
            nonce, resource_owner_key=None):
            return not (client_key, nonce, timestamp, resource_owner_key) in self.nonces                

        def validate_client_key(self, client_key):
            return client_key in self.clients

        def validate_resource_owner_key(self, client_key, resource_owner_key):
            return (self.owners.get(client_key) and 
                    resource_owner_key in self.owners.get(client_key))

        def validate_realm(self, client_key, resource_owner_key, realm, uri):
            return ((client_key, resource_owner_key) in self.assigned_realms and
                     realm in self.assigned_realms.get((client_key, resource_owner_key)))

        def validate_verifier(self, client_key, resource_owner_key, verifier):
            return ((client_key, resource_owner_key) in self.verifiers and
                     safe_compare(verifier, self.verifiers.get(
                        (client_key, resource_owner_key))))

        def validate_redirect_uri(self, client_key, redirect_uri):
            return True

        def get_client_secret(self, client_key):
            return u'super secret'

        def get_resource_owner_secret(self, client_key, resource_owner_key):
            return u'even more secret'

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

        uri, headers, body = c.sign(u'http://server.example.com:80/init')
        self.assertTrue(s.verify_request(uri, body=body, headers=headers))

        uri, headers, body = d.sign(u'http://server.example.com:80/init')
        self.assertTrue(s.verify_request(uri, body=body, headers=headers))

    def test_server_callback_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
            callback_uri=u'http://client.example.com/callback'
        )

        uri, headers, body = c.sign(u'http://server.example.com:80/init')

        s = self.TestServer()
        self.assertTrue(s.verify_request(uri, body=body, headers=headers))

    def test_not_implemented(self):
        s = Server()
        self.assertRaises(NotImplementedError, s.get_client_secret, None)
        self.assertRaises(NotImplementedError, s.get_resource_owner_secret, None, None)
        self.assertRaises(NotImplementedError, lambda: s.dummy_client)
        self.assertRaises(NotImplementedError, lambda: s.dummy_resource_owner)
        self.assertRaises(NotImplementedError, s.get_rsa_key, None)
        self.assertRaises(NotImplementedError, s.validate_client_key, None)
        self.assertRaises(NotImplementedError, s.validate_resource_owner_key, None, None)
        self.assertRaises(NotImplementedError, s.validate_timestamp_and_nonce,
            None, None, None, None)
        self.assertRaises(NotImplementedError, s.validate_redirect_uri, None, None)
        self.assertRaises(NotImplementedError, s.validate_realm, None, None, None, None)
        self.assertRaises(NotImplementedError, s.validate_verifier, None, None, None)

    def test_enforce_ssl(self):
        """Ensure SSL is enforced by default."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, u'http://example.com')

    def test_multiple_source_params(self):
        """Check for duplicate params"""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/?oauth_signature_method=HMAC-SHA1',
            body=u'oauth_version=foo')
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/?oauth_signature_method=HMAC-SHA1',
            headers={u'Authorization' : u'OAuth oauth_signature="foo"'})
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/?oauth_signature_method=HMAC-SHA1',
            body=u'oauth_version=foo',
            headers={u'Authorization' : u'OAuth oauth_signature="foo"'})
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
            body=u'oauth_signature=foo',
            headers={u'Authorization' : u'OAuth oauth_signature_method="foo"'})

    def test_duplicate_params(self):
        """Ensure params are only supplied once"""

        s = Server()
        self.assertRaises(ValueError, s.verify_request, 
            u'https://a.b/?oauth_version=a&oauth_version=b')
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
            body=u'oauth_version=a&oauth_version=b')
        
        # TODO: dict() in parse keqv list auto removes duplicates, wrong? 
        #self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
        #    headers= { u'Authorization' : u'OAuth oauth_version="a",oauth_version="b"' })

    def test_mandated_params(self):
        """Ensure all mandatory params are present."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/')
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce'))
          
    def test_oauth_version(self):
        """OAuth version must be 1.0 if present."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   u'oauth_timestamp=a&oauth_signature_method=RSA-SHA1&'
                   u'oauth_version=2.0')) 

    def test_oauth_timestamp(self):
        """Check for a valid UNIX timestamp."""
        s = Server()
        # Invalid timestamp length, must be 10
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   u'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   u'oauth_timestamp=123456789')) 
        # Invalid timestamp age, must be younger than 10 minutes
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   u'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   u'oauth_timestamp=1234567890')) 
        # Timestamp must be an integer
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   u'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   u'oauth_timestamp=123456789a')) 

    def test_signature_method_validation(self):
        """Ensure valid signature method is used."""

        body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
              u'oauth_version=1.0&oauth_signature_method=%s&'
              u'oauth_timestamp=1234567890')
    
        uri = u'https://example.com/'

        class HMACServer(Server):
            
            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_HMAC,)

        s = HMACServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'RSA-SHA1') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'PLAINTEXT') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'shibboleth') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'') 

        class RSAServer(Server):
            
            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_RSA,)

        s = RSAServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'HMAC-SHA1') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'PLAINTEXT') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'shibboleth') 

        class PlainServer(Server):
            
            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_PLAINTEXT,)

        s = PlainServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'HMAC-SHA1') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'RSA-SHA1') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'shibboleth') 

    def test_check_methods(self):
        """Ensure values are correctly formatted.
        
        Default setting is to only allow alphanumeric characters and a length
        between 20 and 30 characters.
        """
        #TODO: injection attacks, file traversal
        ts = int(time.time())

        client=(u'oauth_signature=a&oauth_timestamp=%s&oauth_nonce=c&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_token=abcdefghijklmnopqrstuvxyz&'
              u'oauth_consumer_key=%s')
    
        owner=(u'oauth_signature=a&oauth_timestamp=%s&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              u'oauth_token=%s')

        nonce=(u'oauth_signature=a&oauth_timestamp=%s&oauth_nonce=%s&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_token=abcdefghijklmnopqrstuvxyz&'
              u'oauth_consumer_key=abcdefghijklmnopqrstuvwxyz')

        realm=(u'oauth_signature=a&oauth_timestamp=%s&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              u'oauth_token=abcdefghijklmnopqrstuvxyz&'
              u'realm=%s')

        verifier=(u'oauth_signature=a&oauth_timestamp=%s&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              u'oauth_token=abcdefghijklmnopqrstuvxyz&'
              u'oauth_verifier=%s')

        uri = u'https://example.com/'
        s = Server()

        # Invalid characters
        invalid = (ts, u'%C3%A5abcdefghijklmnopqrstuvwxyz')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % invalid)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % invalid)
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % invalid)
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % invalid,
            require_verifier=True)

        # Too short
        short = (ts, u'abcdefghi')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % short)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % short)
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % short)
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % short,
            require_verifier=True)

        # Too long
        loong = (ts, u'abcdefghijklmnopqrstuvwxyz123456789')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % loong) 
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % loong) 
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % loong) 
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % loong,
            require_verifier=True) 

        # By default no realms are allowed
        test = (ts, u'shibboleth')
        self.assertRaises(ValueError, s.verify_request, uri, body=realm % test,
            require_realm=True)

        # Missing required owner
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % (ts, u'')) 

        # Missing required verifier
        self.assertRaises(ValueError, s.verify_request, uri, body=realm % test,
            require_verifier=True)

        # Missing required realm
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % test,
            require_realm=True)

    def test_client_validation(self):
        uri = u'https://example.com/'
        client = (u'oauth_signature=fmrXnTF4lO4o%2BD0%2FlZaJHP%2FXqEY%3D&'
              u'oauth_timestamp=1234567890&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_token=abcdefghijklmnopqrstuvxyz&'
              u'oauth_consumer_key={0}')

        s = self.ClientServer()
        self.assertFalse(s.verify_request(uri, body=client.format(u'bar')))
        self.assertTrue(s.verify_request(uri, body=client.format(u'foo')))

    def test_nonce_and_timestamp_validation(self):
        uri = u'https://example.com/'
        replay = (u'oauth_signature=fmrXnTF4lO4o%2BD0%2FlZaJHP%2FXqEY%3D&'
              u'oauth_timestamp=1234567891&'
              u'oauth_nonce=once&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_token=fez&'
              u'oauth_consumer_key=foo')

        s = self.ClientServer()
        self.assertFalse(s.verify_request(uri, body=replay))

    def test_resource_owner_validation(self):
        uri = u'https://example.com/'
        no_owner = (u'oauth_signature=Caupx4p518D7HzA6ihWwV4kB93A%3D&'
              u'oauth_timestamp=1234567890&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=foo')

        invalid_owner = (u'oauth_signature=B0FUgxzDNOPzol0gTTlXREelYrU%3D&'
              u'oauth_timestamp=1234567890&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_token=invalid&'
              u'oauth_consumer_key=foo')

        s = self.ClientServer()
        self.assertTrue(s.verify_request(uri, body=no_owner,
            require_resource_owner=False))
        self.assertFalse(s.verify_request(uri, body=invalid_owner))

    def test_signature_verification(self):
        uri = u'https://example.com/'
        short_sig = (u'oauth_signature=fmrXnTF4lO4o%2BD0%2FlZaJHP%2FXqEY&'
              u'oauth_timestamp=1234567890&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_token=abcdefghijklmnopqrstuvxyz&'
              u'oauth_consumer_key=foo')

        plain = (u'oauth_signature=correctlengthbutthewrongcontent1111&'
              u'oauth_timestamp=1234567890&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=PLAINTEXT&'
              u'oauth_token=abcdefghijklmnopqrstuvxyz&'
              u'oauth_consumer_key=foo')

        s = self.ClientServer()
        self.assertFalse(s.verify_request(uri, body=short_sig))
        self.assertFalse(s.verify_request(uri, body=plain))

    def test_realm_validation(self):
        uri = u'https://example.com/'
        realm = (u'oauth_signature=qra7%2Bl70DVl34ezNbsBnoPnbrss%3D&'
              u'oauth_timestamp=1234567890&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_token=fez&'
              u'oauth_consumer_key=foo&realm=photos')

        s = self.ClientServer()
        self.assertTrue(s.verify_request(uri, body=realm,
            require_realm=True))

    def test_verifier_validation(self):    
        uri = u'https://example.com/'
        verifier = (u'oauth_signature=6AsWnRg%2BZnvfJOZKgaC5JKrF3Pk%3D&'
              u'oauth_timestamp=1234567890&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_token=fez&oauth_consumer_key=foo&'
              u'oauth_verifier=shibboleth')

        s = self.ClientServer()
        self.assertTrue(s.verify_request(uri, body=verifier,
            require_verifier=True))
    
    def test_timing_attack(self):
        """Ensure near constant time verification."""
        #TODO:
        pass
