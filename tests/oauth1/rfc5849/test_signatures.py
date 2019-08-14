# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from oauthlib.common import unicode_type
from oauthlib.oauth1.rfc5849.signature import (collect_parameters,
                                               signature_base_string,
                                               base_string_uri,
                                               normalize_parameters,
                                               sign_hmac_sha1,
                                               sign_hmac_sha1_with_client,
                                               sign_plaintext,
                                               sign_plaintext_with_client,
                                               sign_rsa_sha1,
                                               sign_rsa_sha1_with_client)

from ...unittest import TestCase

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote



class SignatureTests(TestCase):
    class MockClient(dict):
        def __getattr__(self, name):
            return self[name]

        def __setattr__(self, name, value):
            self[name] = value

        def decode(self):
            for k, v in self.items():
                self[k] = v.decode('utf-8')

    uri_query = "b5=%3D%253D&a3=a&c%40=&a2=r%20b"
    authorization_header = """OAuth realm="Example",
    oauth_consumer_key="9djdj82h48djs9d2",
    oauth_token="kkk9d7dh3k39sjv7",
    oauth_signature_method="HMAC-SHA1",
    oauth_timestamp="137131201",
    oauth_nonce="7d8f3e4a",
    oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D" """.strip()
    body = "c2&a3=2+q"
    http_method = b"post"
    base_string_url = (
        "http://example.com/request?{}".format(uri_query)).encode('utf-8')
    unnormalized_request_parameters =[
        ('OAuth realm',"Example"),
        ('oauth_consumer_key',"9djdj82h48djs9d2"),
        ('oauth_token',"kkk9d7dh3k39sjv7"),
        ('oauth_signature_method',"HMAC-SHA1"),
        ('oauth_timestamp',"137131201"),
        ('oauth_nonce',"7d8f3e4a"),
        ('oauth_signature',"bYT5CMsGcbgUdFHObYMEfcx6bsw%3D")
    ]
    normalized_encoded_request_params = sorted(
        [(quote(k), quote(v)) for k, v in unnormalized_request_parameters
         if k.lower() != "oauth realm"])
    client_secret = b"ECrDNoq1VYzzzzzzzzzyAK7TwZNtPnkqatqZZZZ"
    resource_owner_secret = b"just-a-string    asdasd"
    control_base_string = (
        "POST&http%3A%2F%2Fexample.com%2Frequest&"
        "a2%3Dr%2520b%26"
        "a3%3D2%2520q%26"
        "a3%3Da%26"
        "b5%3D%253D%25253D%26"
        "c%2540%3D%26"
        "c2%3D%26"
        "oauth_consumer_key%3D9djdj82h48djs9d2%26"
        "oauth_nonce%3D7d8f3e4a%26"
        "oauth_signature_method%3DHMAC-SHA1%26"
        "oauth_timestamp%3D137131201%26"
        "oauth_token%3Dkkk9d7dh3k39sjv7"
    )

    def setUp(self):
        self.client = self.MockClient(
            client_secret = self.client_secret,
            resource_owner_secret = self.resource_owner_secret
        )

    def test_signature_base_string(self):
        """
        Example text to be turned into a base string::

            POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
            Host: example.com
            Content-Type: application/x-www-form-urlencoded
            Authorization: OAuth realm="Example",
                           oauth_consumer_key="9djdj82h48djs9d2",
                           oauth_token="kkk9d7dh3k39sjv7",
                           oauth_signature_method="HMAC-SHA1",
                           oauth_timestamp="137131201",
                           oauth_nonce="7d8f3e4a",
                           oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
            c2&a3=2+q

        Sample Base string generated and tested against::
            POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q
            %26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_
            key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m
            ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk
            9d7dh3k39sjv7
        """

        self.assertRaises(ValueError, base_string_uri, self.base_string_url)
        base_string_url = base_string_uri(self.base_string_url.decode('utf-8'))
        base_string_url = base_string_url.encode('utf-8')
        querystring = self.base_string_url.split(b'?', 1)[1]
        self.assertRaises(ValueError, collect_parameters, querystring)
        query_params = collect_parameters(querystring.decode('utf-8'),
                                          body=self.body)
        normalized_encoded_query_params = sorted(
            [(quote(k), quote(v)) for k, v in query_params])
        normalized_request_string = "&".join(sorted(
            ['='.join((k, v)) for k, v in (
                        self.normalized_encoded_request_params +
                        normalized_encoded_query_params)
             if k.lower() != 'oauth_signature']))
        self.assertRaises(ValueError, signature_base_string,
                          self.http_method,
                          base_string_url,
                          normalized_request_string)
        self.assertRaises(ValueError, signature_base_string,
                          self.http_method.decode('utf-8'),
                          base_string_url,
                          normalized_request_string)

        base_string = signature_base_string(
            self.http_method.decode('utf-8'),
            base_string_url.decode('utf-8'),
            normalized_request_string
        )

        self.assertEqual(self.control_base_string, base_string)

    def test_base_string_uri(self):
        """
        Example text to be turned into a normalized base string uri::

            GET /?q=1 HTTP/1.1
            Host: www.example.net:8080

        Sample string generated::

            https://www.example.net:8080/
        """

        # test first example from RFC 5849 section 3.4.1.2.
        # Note: there is a space between "r" and "v"
        uri = 'http://EXAMPLE.COM:80/r v/X?id=123'
        self.assertEqual(base_string_uri(uri),
                         'http://example.com/r%20v/X')

        # test second example from RFC 5849 section 3.4.1.2.
        uri = 'https://www.example.net:8080/?q=1'
        self.assertEqual(base_string_uri(uri),
                         'https://www.example.net:8080/')

        # test for unicode failure
        uri = b"www.example.com:8080"
        self.assertRaises(ValueError, base_string_uri, uri)

        # test for missing scheme
        uri = "www.example.com:8080"
        self.assertRaises(ValueError, base_string_uri, uri)

        # test a URI with the default port
        uri = "http://www.example.com:80/"
        self.assertEqual(base_string_uri(uri),
                         "http://www.example.com/")

        # test a URI missing a path
        uri = "http://www.example.com"
        self.assertEqual(base_string_uri(uri),
                         "http://www.example.com/")

        # test a relative URI
        uri = "/a-host-relative-uri"
        host = "www.example.com"
        self.assertRaises(ValueError, base_string_uri, (uri, host))

        # test overriding the URI's netloc with a host argument
        uri = "http://www.example.com/a-path"
        host = "alternatehost.example.com"
        self.assertEqual(base_string_uri(uri, host),
                         "http://alternatehost.example.com/a-path")

    def test_collect_parameters(self):
        """We check against parameters multiple times in case things change
        after more parameters are added.
        """
        self.assertEqual(collect_parameters(), [])

        # Check against uri_query
        parameters = collect_parameters(uri_query=self.uri_query)
        correct_parameters = [('b5', '=%3D'),
                              ('a3', 'a'),
                              ('c@', ''),
                              ('a2', 'r b')]
        self.assertEqual(sorted(parameters), sorted(correct_parameters))

        headers = {'Authorization': self.authorization_header}
        # check against authorization header as well
        parameters = collect_parameters(
            uri_query=self.uri_query, headers=headers)
        parameters_with_realm = collect_parameters(
            uri_query=self.uri_query, headers=headers, with_realm=True)
        # Redo the checks against all the parameters. Duplicated code but
        # better safety
        correct_parameters += [
            ('oauth_nonce', '7d8f3e4a'),
            ('oauth_timestamp', '137131201'),
            ('oauth_consumer_key', '9djdj82h48djs9d2'),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_token', 'kkk9d7dh3k39sjv7')]
        correct_parameters_with_realm = (
            correct_parameters + [('realm', 'Example')])
        self.assertEqual(sorted(parameters), sorted(correct_parameters))
        self.assertEqual(sorted(parameters_with_realm),
                         sorted(correct_parameters_with_realm))

        # Add in the body.
        # Redo again the checks against all the parameters. Duplicated code
        # but better safety
        parameters = collect_parameters(
            uri_query=self.uri_query, body=self.body, headers=headers)
        correct_parameters += [
            ('c2', ''),
            ('a3', '2 q')
        ]
        self.assertEqual(sorted(parameters), sorted(correct_parameters))

    def test_normalize_parameters(self):
        """ We copy some of the variables from the test method above."""

        headers = {'Authorization': self.authorization_header}
        parameters = collect_parameters(
            uri_query=self.uri_query, body=self.body, headers=headers)
        normalized = normalize_parameters(parameters)

        # Unicode everywhere and always
        self.assertIsInstance(normalized, unicode_type)

        # Lets see if things are in order
        # check to see that querystring keys come in alphanumeric order:
        querystring_keys = ['a2', 'a3', 'b5', 'oauth_consumer_key',
                            'oauth_nonce', 'oauth_signature_method',
                            'oauth_timestamp', 'oauth_token']
        index = -1  # start at -1 because the 'a2' key starts at index 0
        for key in querystring_keys:
            self.assertGreater(normalized.index(key), index)
            index = normalized.index(key)

    # Control signature created using openssl:
    # echo -n $(cat <message>) | openssl dgst -binary -hmac <key> | base64
    control_signature = "mwd09YMxVd2XJ1gudNaBuAuKKuY="
    control_signature_s = "wsdNmjGB7lvis0UJuPAmjvX/PXw="

    def test_sign_hmac_sha1(self):
        """Verifying HMAC-SHA1 signature against one created by OpenSSL."""

        self.assertRaises(ValueError, sign_hmac_sha1, self.control_base_string,
                          self.client_secret, self.resource_owner_secret)

        sign = sign_hmac_sha1(self.control_base_string,
                              self.client_secret.decode('utf-8'),
                              b'')
        self.assertEqual(len(sign), 28)
        self.assertEqual(sign, self.control_signature)

    def test_sign_hmac_sha1_with_secret(self):
        """Verifying HMAC-SHA1 signature against one created by OpenSSL."""

        self.assertRaises(ValueError, sign_hmac_sha1, self.control_base_string,
                          self.client_secret, self.resource_owner_secret)

        sign = sign_hmac_sha1(self.control_base_string,
                              self.client_secret.decode('utf-8'),
                              self.resource_owner_secret.decode('utf-8'))
        self.assertEqual(len(sign), 28)
        self.assertEqual(sign, self.control_signature_s)

    def test_sign_hmac_sha1_with_client(self):
        self.assertRaises(ValueError,
            sign_hmac_sha1_with_client,
            self.control_base_string,
            self.client)

        self.client.decode()
        sign = sign_hmac_sha1_with_client(
            self.control_base_string, self.client)

        self.assertEqual(len(sign), 28)
        self.assertEqual(sign, self.control_signature_s)


    control_base_string_rsa_sha1 = (
        b"POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q"
        b"%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_"
        b"key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m"
        b"ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk"
        b"9d7dh3k39sjv7"
    )

    # Generated using: $ openssl genrsa -out <key>.pem 1024
    # PEM encoding requires the key to be concatenated with
    # linebreaks.
    rsa_private_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDk1/bxyS8Q8jiheHeYYp/4rEKJopeQRRKKpZI4s5i+UPwVpupG
AlwXWfzXwSMaKPAoKJNdu7tqKRniqst5uoHXw98gj0x7zamu0Ck1LtQ4c7pFMVah
5IYGhBi2E9ycNS329W27nJPWNCbESTu7snVlG8V8mfvGGg3xNjTMO7IdrwIDAQAB
AoGBAOQ2KuH8S5+OrsL4K+wfjoCi6MfxCUyqVU9GxocdM1m30WyWRFMEz2nKJ8fR
p3vTD4w8yplTOhcoXdQZl0kRoaDzrcYkm2VvJtQRrX7dKFT8dR8D/Tr7dNQLOXfC
DY6xveQczE7qt7Vk7lp4FqmxBsaaEuokt78pOOjywZoInjZhAkEA9wz3zoZNT0/i
rf6qv2qTIeieUB035N3dyw6f1BGSWYaXSuerDCD/J1qZbAPKKhyHZbVawFt3UMhe
542UftBaxQJBAO0iJy1I8GQjGnS7B3yvyH3CcLYGy296+XO/2xKp/d/ty1OIeovx
C60pLNwuFNF3z9d2GVQAdoQ89hUkOtjZLeMCQQD0JO6oPHUeUjYT+T7ImAv7UKVT
Suy30sKjLzqoGw1kR+wv7C5PeDRvscs4wa4CW9s6mjSrMDkDrmCLuJDtmf55AkEA
kmaMg2PNrjUR51F0zOEFycaaqXbGcFwe1/xx9zLmHzMDXd4bsnwt9kk+fe0hQzVS
JzatanQit3+feev1PN3QewJAWv4RZeavEUhKv+kLe95Yd0su7lTLVduVgh4v5yLT
Ga6FHdjGPcfajt+nrpB1n8UQBEH9ZxniokR/IPvdMlxqXA==
-----END RSA PRIVATE KEY-----
"""
    @property
    def control_signature_rsa_sha1(self):
        # Base string saved in "<message>". Signature obtained using:
        # $ echo -n $(cat <msg>) | openssl dgst -sha1 -sign <key>.pem | base64
        # where echo -n suppresses the last linebreak.
        return (
            "mFY2KOEnlYWsTvUA+5kxuBIcvBYXu+ljw9ttVJQxKduMueGSVPCB1tK1PlqVLK738"
            "HK0t19ecBJfb6rMxUwrriw+MlBO+jpojkZIWccw1J4cAb4qu4M81DbpUAq4j/1w/Q"
            "yTR4TWCODlEfN7Zfgy8+pf+TjiXfIwRC1jEWbuL1E="

        )

    def test_sign_rsa_sha1(self):
        """Verify RSA-SHA1 signature against one created by OpenSSL."""
        base_string = self.control_base_string_rsa_sha1

        private_key = self.rsa_private_key

        control_signature = self.control_signature_rsa_sha1

        sign = sign_rsa_sha1(base_string, private_key)
        self.assertEqual(sign, control_signature)
        sign = sign_rsa_sha1(base_string.decode('utf-8'), private_key)
        self.assertEqual(sign, control_signature)


    def test_sign_rsa_sha1_with_client(self):
        base_string = self.control_base_string_rsa_sha1

        self.client.rsa_key = self.rsa_private_key

        control_signature = self.control_signature_rsa_sha1

        sign = sign_rsa_sha1_with_client(base_string, self.client)

        self.assertEqual(sign, control_signature)

        self.client.decode() ## Decode `rsa_private_key` from UTF-8

        sign = sign_rsa_sha1_with_client(base_string, self.client)

        self.assertEqual(sign, control_signature)


    control_signature_plaintext = (
        "ECrDNoq1VYzzzzzzzzzyAK7TwZNtPnkqatqZZZZ&"
        "just-a-string%20%20%20%20asdasd")

    def test_sign_plaintext(self):
        """ """

        self.assertRaises(ValueError, sign_plaintext, self.client_secret,
                          self.resource_owner_secret)
        sign = sign_plaintext(self.client_secret.decode('utf-8'),
                              self.resource_owner_secret.decode('utf-8'))
        self.assertEqual(sign, self.control_signature_plaintext)


    def test_sign_plaintext_with_client(self):
        self.assertRaises(ValueError, sign_plaintext_with_client,
                          None, self.client)

        self.client.decode()

        sign = sign_plaintext_with_client(None, self.client)

        self.assertEqual(sign, self.control_signature_plaintext)
