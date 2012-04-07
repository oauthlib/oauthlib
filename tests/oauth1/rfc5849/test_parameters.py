# -*- coding: utf-8 -*-
from __future__ import absolute_import
from oauthlib.oauth1.rfc5849.parameters import *
from ...unittest import TestCase


class ParameterTests(TestCase):
    auth_only_params = [
        (u'oauth_consumer_key', u"9djdj82h48djs9d2"),
        (u'oauth_token', u"kkk9d7dh3k39sjv7"),
        (u'oauth_signature_method', u"HMAC-SHA1"),
        (u'oauth_timestamp', u"137131201"),
        (u'oauth_nonce', u"7d8f3e4a"),
        (u'oauth_signature', u"bYT5CMsGcbgUdFHObYMEfcx6bsw=")
    ]
    auth_and_data = list(auth_only_params)
    auth_and_data.append((u'data_param_foo', u'foo'))
    auth_and_data.append((u'data_param_1', u'1'))
    realm = u'testrealm'
    norealm_authorization_header = ' '.join((
        'OAuth',
        'oauth_consumer_key="9djdj82h48djs9d2",',
        'oauth_token="kkk9d7dh3k39sjv7",',
        'oauth_signature_method="HMAC-SHA1",',
        'oauth_timestamp="137131201",',
        'oauth_nonce="7d8f3e4a",',
        'oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"',
    ))
    withrealm_authorization_header = ' '.join((
        'OAuth',
        'realm="testrealm",',
        'oauth_consumer_key="9djdj82h48djs9d2",',
        'oauth_token="kkk9d7dh3k39sjv7",',
        'oauth_signature_method="HMAC-SHA1",',
        'oauth_timestamp="137131201",',
        'oauth_nonce="7d8f3e4a",',
        'oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"',
    ))

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

    def test_prepare_headers(self):
        self.assertEqual(
            prepare_headers(self.auth_only_params, {}),
            {'Authorization': self.norealm_authorization_header})
        self.assertEqual(
            prepare_headers(self.auth_only_params, {}, realm=self.realm),
            {'Authorization': self.withrealm_authorization_header})

    def test_prepare_headers_ignore_data(self):
        self.assertEqual(
            prepare_headers(self.auth_and_data, {}),
            {'Authorization': self.norealm_authorization_header})
        self.assertEqual(
            prepare_headers(self.auth_and_data, {}, realm=self.realm),
            {'Authorization': self.withrealm_authorization_header})

    def test_prepare_form_encoded_body(self):
        existing_body = u''
        form_encoded_body = 'data_param_foo=foo&data_param_1=1&oauth_signature=bYT5CMsGcbgUdFHObYMEfcx6bsw%3D&oauth_nonce=7d8f3e4a&oauth_timestamp=137131201&oauth_signature_method=HMAC-SHA1&oauth_token=kkk9d7dh3k39sjv7&oauth_consumer_key=9djdj82h48djs9d2'
        self.assertEqual(
            prepare_form_encoded_body(self.auth_and_data, existing_body),
            form_encoded_body)

    def test_prepare_request_uri_query(self):
        url = u'http://notarealdomain.com/foo/bar/baz?some=args&go=here'
        request_uri_query = u'http://notarealdomain.com/foo/bar/baz?some=args&go=here&data_param_foo=foo&data_param_1=1&oauth_signature=bYT5CMsGcbgUdFHObYMEfcx6bsw%3D&oauth_nonce=7d8f3e4a&oauth_timestamp=137131201&oauth_signature_method=HMAC-SHA1&oauth_token=kkk9d7dh3k39sjv7&oauth_consumer_key=9djdj82h48djs9d2'
        self.assertEqual(
            prepare_request_uri_query(self.auth_and_data, url),
            request_uri_query)
