# -*- coding: utf-8 -*-
from unittest import mock
from urllib.parse import urlencode

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.openid import RequestValidator
from oauthlib.openid.connect.core.grant_types.hybrid import HybridGrant

from tests.oauth2.rfc6749.grant_types.test_authorization_code import (
    AuthorizationCodeGrantTest,
)
from tests.unittest import TestCase

from .test_authorization_code import OpenIDAuthCodeTest


class OpenIDHybridInterferenceTest(AuthorizationCodeGrantTest):
    """Test that OpenID don't interfere with normal OAuth 2 flows."""

    def setUp(self):
        super().setUp()
        self.auth = HybridGrant(request_validator=self.mock_validator)


class OpenIDHybridCodeTokenTest(OpenIDAuthCodeTest):

    def setUp(self):
        super().setUp()
        self.request.response_type = 'code token'
        self.request.nonce = None
        self.auth = HybridGrant(request_validator=self.mock_validator)
        self.url_query = 'https://a.b/cb?code=abc&state=abc&token_type=Bearer&expires_in=3600&scope=hello+openid&access_token=abc'
        self.url_fragment = 'https://a.b/cb#code=abc&state=abc&token_type=Bearer&expires_in=3600&scope=hello+openid&access_token=abc'

    @mock.patch('oauthlib.common.generate_token')
    def test_optional_nonce(self, generate_token):
        generate_token.return_value = 'abc'
        self.request.nonce = 'xyz'
        _scope, _info = self.auth.validate_authorization_request(self.request)

        bearer = BearerToken(self.mock_validator)
        h, b, s = self.auth.create_authorization_response(self.request, bearer)
        self.assertURLEqual(h['Location'], self.url_fragment, parse_fragment=True)
        self.assertIsNone(b)
        self.assertEqual(s, 302)


class OpenIDHybridCodeIdTokenTest(OpenIDAuthCodeTest):

    def setUp(self):
        super().setUp()
        self.mock_validator.get_code_challenge.return_value = None
        self.request.response_type = 'code id_token'
        self.request.nonce = 'zxc'
        self.auth = HybridGrant(request_validator=self.mock_validator)
        token = 'MOCKED_TOKEN'
        self.url_query = 'https://a.b/cb?code=abc&state=abc&id_token=%s' % token
        self.url_fragment = 'https://a.b/cb#code=abc&state=abc&id_token=%s' % token

    @mock.patch('oauthlib.common.generate_token')
    def test_required_nonce(self, generate_token):
        generate_token.return_value = 'abc'
        self.request.nonce = None
        self.assertRaises(errors.InvalidRequestError, self.auth.validate_authorization_request, self.request)

        bearer = BearerToken(self.mock_validator)
        h, b, s = self.auth.create_authorization_response(self.request, bearer)
        self.assertIn('#error=invalid_request', h['Location'])
        self.assertIsNone(b)
        self.assertEqual(s, 302)

    def test_id_token_contains_nonce(self):
        token = {}
        self.mock_validator.get_id_token.side_effect = None
        self.mock_validator.get_id_token.return_value = None
        token = self.auth.add_id_token(token, None, self.request)
        assert self.mock_validator.finalize_id_token.call_count == 1
        claims = self.mock_validator.finalize_id_token.call_args[0][0]
        assert "nonce" in claims


class OpenIDHybridCodeIdTokenTokenTest(OpenIDAuthCodeTest):

    def setUp(self):
        super().setUp()
        self.mock_validator.get_code_challenge.return_value = None
        self.request.response_type = 'code id_token token'
        self.request.nonce = 'xyz'
        self.auth = HybridGrant(request_validator=self.mock_validator)
        token = 'MOCKED_TOKEN'
        self.url_query = 'https://a.b/cb?code=abc&state=abc&token_type=Bearer&expires_in=3600&scope=hello+openid&access_token=abc&id_token=%s' % token
        self.url_fragment = 'https://a.b/cb#code=abc&state=abc&token_type=Bearer&expires_in=3600&scope=hello+openid&access_token=abc&id_token=%s' % token

    @mock.patch('oauthlib.common.generate_token')
    def test_required_nonce(self, generate_token):
        generate_token.return_value = 'abc'
        self.request.nonce = None
        self.assertRaises(errors.InvalidRequestError, self.auth.validate_authorization_request, self.request)

        bearer = BearerToken(self.mock_validator)
        h, b, s = self.auth.create_authorization_response(self.request, bearer)
        self.assertIn('#error=invalid_request', h['Location'])
        self.assertIsNone(b)
        self.assertEqual(s, 302)


class OpenIDHybridResponseModeTest(TestCase):
    """Unsupported response modes must not redirect, see #983."""

    def setUp(self):
        self.mock_validator = mock.Mock(spec=RequestValidator)
        self.mock_validator.validate_client_id.return_value = True
        self.mock_validator.validate_redirect_uri.return_value = True
        self.mock_validator.validate_response_type.return_value = True
        self.mock_validator.is_pkce_required.return_value = False
        self.mock_validator.validate_scopes.return_value = False
        self.auth = HybridGrant(self.mock_validator)

    def make_request(self, response_type, response_mode):
        params = {
            "client_id": "client",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid invalid",
            "nonce": "nonce",
            "state": "state",
        }
        if response_type is not None:
            params["response_type"] = response_type
        if response_mode is not None:
            params["response_mode"] = response_mode
        return Request("https://server.example/authorize?" + urlencode(params))

    def test_unsupported_response_mode(self):
        for response_type in ("code id_token", "not-a-type", None):
            with self.subTest(response_type=response_type):
                self.mock_validator.validate_response_type.reset_mock()
                request = self.make_request(response_type, "not-a-mode")
                with self.assertRaises(errors.UnsupportedResponseModeError) as cm:
                    self.auth.create_authorization_response(request, None)
                self.assertEqual(cm.exception.status_code, 400)
                self.assertFalse(self.mock_validator.validate_response_type.called)

                request = self.make_request(response_type, "not-a-mode")
                self.assertRaises(errors.UnsupportedResponseModeError,
                                  self.auth.validate_authorization_request, request)

    def test_default_response_mode(self):
        for response_type in ("code id_token", "not-a-type", None):
            with self.subTest(response_type=response_type):
                request = self.make_request(response_type, None)
                h, _b, s = self.auth.create_authorization_response(request, None)
                self.assertEqual(s, 302)
                self.assertTrue(h['Location'].startswith('https://client.example/cb#error='))

    def test_empty_response_mode(self):
        request = self.make_request("code id_token", "")
        h, _b, s = self.auth.create_authorization_response(request, None)
        self.assertEqual(s, 302)
        self.assertTrue(h['Location'].startswith('https://client.example/cb#error='))

    def test_error_in_uri_uses_fragment(self):
        request = self.make_request("code id_token", None)
        with self.assertRaises(errors.InvalidScopeError) as cm:
            self.auth.validate_authorization_request(request)
        uri = cm.exception.in_uri(cm.exception.redirect_uri)
        self.assertTrue(uri.startswith('https://client.example/cb#error=invalid_scope'))
