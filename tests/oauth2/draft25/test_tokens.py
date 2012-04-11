from __future__ import absolute_import

from ...unittest import TestCase

from oauthlib.oauth2.draft25.tokens import *


class TokenTest(TestCase):

    # MAC without body/payload or extension
    mac_plain = {
        u'token': u'h480djs93hd8',
        u'uri': u'http://example.com/resource/1?b=1&a=2',
        u'key': u'489dks293j39',
        u'http_method': u'GET',
        u'nonce': u'264095:dj83hs9s',
        u'hash_algorithm': u'hmac-sha-1'
    }
    auth_plain = {
        u'Authorization': u'MAC id="h480djs93hd8", nonce="264095:dj83hs9s",'
        ' mac="SLDJd4mg43cjQfElUs3Qub4L6xE="'
    }

    # MAC with body/payload, no extension
    mac_body = {
        u'token': u'jd93dh9dh39D',
        u'uri': u'http://example.com/request',
        u'key': u'8yfrufh348h',
        u'http_method': u'POST',
        u'nonce': u'273156:di3hvdf8',
        u'hash_algorithm': u'hmac-sha-1',
        u'body': u'hello=world%21'
    }
    auth_body = {
        u'Authorization': u'MAC id="jd93dh9dh39D", nonce="273156:di3hvdf8",'
        ' bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=", mac="W7bdMZbv9UWOTadASIQHagZyirA="'
    }

    # MAC with body/payload and extension
    mac_both = {
        u'token': u'h480djs93hd8',
        u'uri': u'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q',
        u'key': u'489dks293j39',
        u'http_method': u'GET',
        u'nonce': u'264095:7d8f3e4a',
        u'hash_algorithm': u'hmac-sha-1',
        u'body': u'Hello World!',
        u'ext': u'a,b,c'
    }
    auth_both = {
        u'Authorization': u'MAC id="h480djs93hd8", nonce="264095:7d8f3e4a",'
        ' bodyhash="Lve95gjOVATpfV8EL5X4nxwjKHE=", ext="a,b,c",'
        ' mac="Z3C2DojEopRDIC88/imW8Ez853g="'
    }

    # Bearer
    token = u'vF9dft4qmT'
    uri = u'http://server.example.com/resource'
    bearer_headers = {
        u'Authorization': u'Bearer vF9dft4qmT'
    }
    bearer_body = u'access_token=vF9dft4qmT'
    bearer_uri = u'http://server.example.com/resource?access_token=vF9dft4qmT'

    def test_prepare_mac_header(self):
        """Verify mac signatures correctness

        TODO: verify hmac-sha-256
        """
        self.assertEqual(prepare_mac_header(**self.mac_plain), self.auth_plain)
        self.assertEqual(prepare_mac_header(**self.mac_body), self.auth_body)
        self.assertEqual(prepare_mac_header(**self.mac_both), self.auth_both)

    def test_prepare_bearer_request(self):
        """Verify proper addition of bearer tokens to requests.

        They may be represented as query components in body or URI or
        in a Bearer authorization header.
        """
        self.assertEqual(prepare_bearer_headers(self.token), self.bearer_headers)
        self.assertEqual(prepare_bearer_body(self.token), self.bearer_body)
        self.assertEqual(prepare_bearer_uri(self.token, uri=self.uri), self.bearer_uri)
