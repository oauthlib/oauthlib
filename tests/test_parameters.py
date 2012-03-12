from __future__ import absolute_import

from .unittest import TestCase

from oauthlib.parameters import *


class ParameterTests(TestCase):
    def test_order_oauth_parameters(self):
        unordered = {
            'oauth_foo': 'foo',
            'oauth_bar': 'bar',
            'lala': 123,
            'oauth_baz': 'baz', }
        expected = [
            ('oauth_bar', 'bar'),
            ('oauth_baz', 'baz'),
            ('oauth_foo', 'foo'),
            ('lala', 123)]
        self.assertEqual(order_oauth_parameters(unordered), expected)

    def test_prepare_authorization_header(self):
        realm = 'testrealm'
        auth_header_params = {
            'oauth_consumer_key': "9djdj82h48djs9d2",
            'oauth_token': "kkk9d7dh3k39sjv7",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_timestamp': "137131201",
            'oauth_nonce': "7d8f3e4a",
            'oauth_signature': "bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
        }
        norealm = prepare_authorization_header(auth_header_params)
        withrealm = prepare_authorization_header(auth_header_params, realm=realm)
        self.assertEqual(norealm, 'OAuth oauth_nonce=7d8f3e4a,oauth_timestamp=137131201,oauth_consumer_key=9djdj82h48djs9d2,oauth_signature_method=HMAC-SHA1,oauth_token=kkk9d7dh3k39sjv7,oauth_signature=bYT5CMsGcbgUdFHObYMEfcx6bsw%3D')
        self.assertEqual(withrealm, 'OAuth realm=testrealm,oauth_nonce=7d8f3e4a,oauth_timestamp=137131201,oauth_consumer_key=9djdj82h48djs9d2,oauth_signature_method=HMAC-SHA1,oauth_token=kkk9d7dh3k39sjv7,oauth_signature=bYT5CMsGcbgUdFHObYMEfcx6bsw%3D')
