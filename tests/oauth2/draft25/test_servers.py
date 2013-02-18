
"""Test for the various oauth 2 provider endpoints.

The tests focus on shared functionality between the different endpoints to
ensure consistency in both behaviour and provided interfaces.
"""
from __future__ import absolute_import, unicode_literals
import json
import mock
from urlparse import urlparse, parse_qs
from ...unittest import TestCase

from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import WebApplicationServer, MobileApplicationServer
from oauthlib.oauth2 import LegacyApplicationServer, BackendApplicationServer


def get_query_credentials(uri):
    return parse_qs(urlparse(uri).query)


def get_fragment_credentials(uri):
    return parse_qs(urlparse(uri).fragment)


class TestScopeHandling(TestCase):

    DEFAULT_REDIRECT_URI = 'http://i.b./path'

    def set_scopes(self, scopes):
        def set_request_scopes(client_id, code, client, request):
            request.scopes = scopes
            return True
        return set_request_scopes

    def set_user(self, request):
        request.user = 'foo'
        request.client_id = 'bar'
        return True

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = TestScopeHandling.DEFAULT_REDIRECT_URI
        self.web = WebApplicationServer(self.validator)
        self.mobile = MobileApplicationServer(self.validator)
        self.legacy = LegacyApplicationServer(self.validator)
        self.backend = BackendApplicationServer(self.validator)

    def test_scope_extraction(self):
        scopes = (
            ('images', ['images']),
            ('images+videos', ['images', 'videos']),
            ('http%3A%2f%2fa.b%2fvideos', ['http://a.b/videos']),
            ('http%3A%2f%2fa.b%2fvideos+pics', ['http://a.b/videos', 'pics']),
            ('pics+http%3A%2f%2fa.b%2fvideos', ['pics', 'http://a.b/videos']),
            ('http%3A%2f%2fa.b%2fvideos+https%3A%2f%2fc.d%2Fsecret', ['http://a.b/videos', 'https://c.d/secret']),
        )

        uri = 'http://example.com/path?client_id=abc&scope=%s&response_type=%s'
        for scope, correct_scopes in scopes:
            scopes, _ = self.web.validate_authorization_request(
                    uri % (scope, 'code'))
            self.assertItemsEqual(scopes, correct_scopes)
            scopes, _ = self.mobile.validate_authorization_request(
                    uri % (scope, 'token'))
            self.assertItemsEqual(scopes, correct_scopes)

    def test_scope_preservation(self):
        scope = 'pics+http%3A%2f%2fa.b%2fvideos'
        correct_scope = 'pics http%3A%2f%2fa.b%2fvideos'
        decoded_scope = 'pics http://a.b/videos'
        scopes = ['pics', 'http%3A%2f%2fa.b%2fvideos']
        auth_uri = 'http://example.com/path?client_id=abc&scope=%s&%s'
        token_uri = 'http://example.com/path'

        # authorization grant
        uri, _, _, _ = self.web.create_authorization_response(
                auth_uri % (scope, 'response_type=code'))
        self.validator.validate_code.side_effect = self.set_scopes(scopes)
        code = get_query_credentials(uri)['code'][0]
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=%s' % code)
        self.assertEqual(json.loads(body)['scope'], correct_scope)

        # implicit grant
        uri, _, _, _ = self.mobile.create_authorization_response(
                auth_uri % (scope, 'response_type=token'))
        self.assertEqual(get_fragment_credentials(uri)['scope'][0], decoded_scope)

        # resource owner password credentials grant
        body = 'grant_type=password&username=abc&password=secret&scope=%s'
        _, _, body, _ = self.legacy.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

        # client credentials grant
        body = 'grant_type=client_credentials&scope=%s'
        self.validator.authenticate_client.side_effect = self.set_user
        _, _, body, _ = self.backend.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

    def test_scope_changed(self):
        # TODO overwrite validator
        scope = 'pics+http%3A%2f%2fa.b%2fvideos'
        scopes = ['images', 'http://a.b/videos']
        decoded_scope = 'images http://a.b/videos'
        auth_uri = 'http://example.com/path?client_id=abc&scope=%s&%s'
        token_uri = 'http://example.com/path'

        # authorization grant
        uri, _, _, _ = self.web.create_authorization_response(
                auth_uri % (scope, 'response_type=code'))
        code = get_query_credentials(uri)['code'][0]
        self.validator.validate_code.side_effect = self.set_scopes(scopes)
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=%s' % code)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

        # implicit grant
        self.validator.validate_scopes.side_effect = self.set_scopes(scopes)
        uri, _, _, _ = self.mobile.create_authorization_response(
                auth_uri % (scope, 'response_type=token'))
        self.assertEqual(get_fragment_credentials(uri)['scope'][0], decoded_scope)

        # resource owner password credentials grant
        self.validator.validate_scopes.side_effect = self.set_scopes(scopes)
        body = 'grant_type=password&username=abc&password=secret&scope=%s'
        _, _, body, _ = self.legacy.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

        # client credentials grant
        self.validator.validate_scopes.side_effect = self.set_scopes(scopes)
        self.validator.authenticate_client.side_effect = self.set_user
        body = 'grant_type=client_credentials&scope=%s'
        _, _, body, _ = self.backend.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

    def test_invalid_scope(self):
        # invalid, non existing scope
        pass

    def test_unauthorized_scope(self):
        # unauthorized by the user or provider
        pass
