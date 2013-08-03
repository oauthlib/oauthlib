# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from ...unittest import TestCase

import json
import mock
from oauthlib import common
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.errors import UnsupportedGrantTypeError
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError
from oauthlib.oauth2.rfc6749.errors import InvalidClientError
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.grant_types import ImplicitGrant
from oauthlib.oauth2.rfc6749.grant_types import ResourceOwnerPasswordCredentialsGrant
from oauthlib.oauth2.rfc6749.grant_types import ClientCredentialsGrant
from oauthlib.oauth2.rfc6749.grant_types import RefreshTokenGrant
from oauthlib.oauth2.rfc6749.tokens import BearerToken


class RequestValidatorTest(TestCase):

    def test_client_id(self):
        pass

    def test_client(self):
        pass

    def test_response_type(self):
        pass

    def test_scopes(self):
        pass

    def test_redirect_uri(self):
        pass


class AuthorizationCodeGrantTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.expires_in = 1800
        self.request.client = 'batman'
        self.request.client_id = 'abcdef'
        self.request.code = '1234'
        self.request.response_type = 'code'
        self.request.grant_type = 'authorization_code'

        self.request_state = Request('http://a.b/path')
        self.request_state.state = 'abc'

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = self.set_client
        self.auth = AuthorizationCodeGrant(request_validator=self.mock_validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def test_create_authorization_grant(self):
        grant = self.auth.create_authorization_code(self.request)
        self.assertIn('code', grant)

        grant = self.auth.create_authorization_code(self.request_state)
        self.assertIn('code', grant)
        self.assertIn('state', grant)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        h, token, s = self.auth.create_token_response(self.request, bearer)
        token = json.loads(token)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertIn('expires_in', token)
        self.assertIn('scope', token)

    def test_validate_token_request(self):
        mock_validator = mock.MagicMock()
        auth = AuthorizationCodeGrant(request_validator=mock_validator)
        request = Request('http://a.b/path')
        self.assertRaises(UnsupportedGrantTypeError,
                auth.validate_token_request, request)

        request.grant_type = 'authorization_code'
        self.assertRaises(InvalidRequestError,
                auth.validate_token_request, request)

        mock_validator.authenticate_client.return_value = False
        mock_validator.authenticate_client_id.return_value = False
        request.code = 'waffles'
        self.assertRaises(InvalidClientError,
                auth.validate_token_request, request)

        request.client = 'batman'
        mock_validator.authenticate_client = self.set_client
        mock_validator.validate_code.return_value = False
        self.assertRaises(InvalidGrantError,
                auth.validate_token_request, request)


class ImplicitGrantTest(TestCase):

    def setUp(self):
        mock_client = mock.MagicMock()
        mock_client.user.return_value = 'mocked user'
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.client = mock_client
        self.request.client_id = 'abcdef'
        self.request.response_type = 'token'
        self.request.state = 'xyz'
        self.request.redirect_uri = 'https://b.c/p'

        self.mock_validator = mock.MagicMock()
        self.auth = ImplicitGrant(request_validator=self.mock_validator)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator, expires_in=1800)
        orig_generate_token = common.generate_token
        self.addCleanup(setattr, common, 'generate_token', orig_generate_token)
        common.generate_token = lambda *args, **kwargs: '1234'
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        correct_uri = 'https://b.c/p#access_token=1234&token_type=Bearer&expires_in=1800&state=xyz&scope=hello+world'
        self.assertEqual(status_code, 302)
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], correct_uri, parse_fragment=True)

    def test_error_response(self):
        pass


class ResourceOwnerPasswordCredentialsGrantTest(TestCase):

    def setUp(self):
        mock_client = mock.MagicMock()
        mock_client.user.return_value = 'mocked user'
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'password'
        self.request.username = 'john'
        self.request.password = 'doe'
        self.request.client = mock_client
        self.request.scopes = ('mocked', 'scopes')
        self.mock_validator = mock.MagicMock()
        self.auth = ResourceOwnerPasswordCredentialsGrant(
                request_validator=self.mock_validator)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)
        self.assertIn('refresh_token', token)

    def test_error_response(self):
        pass

    def test_scopes(self):
        pass


class ClientCredentialsGrantTest(TestCase):

    def setUp(self):
        mock_client = mock.MagicMock()
        mock_client.user.return_value = 'mocked user'
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'client_credentials'
        self.request.client = mock_client
        self.request.scopes = ('mocked', 'scopes')
        self.mock_validator = mock.MagicMock()
        self.auth = ClientCredentialsGrant(
                request_validator=self.mock_validator)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)

    def test_error_response(self):
        pass

    def test_validate_token_response(self):
        # wrong grant type, scope
        pass


class RefreshTokenGrantTest(TestCase):

    def setUp(self):
        mock_client = mock.MagicMock()
        mock_client.user.return_value = 'mocked user'
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'refresh_token'
        self.request.refresh_token = 'lsdkfhj230'
        self.request.client = mock_client
        self.request.scope = 'foo'
        self.mock_validator = mock.MagicMock()
        self.auth = RefreshTokenGrant(
                request_validator=self.mock_validator)

    def test_create_token_response(self):
        self.mock_validator.get_original_scopes.return_value = ['foo', 'bar']
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)
        self.assertEqual(token['scope'], 'foo')

    def test_create_token_inherit_scope(self):
        self.request.scope = None
        self.mock_validator.get_original_scopes.return_value = ['foo', 'bar']
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)
        self.assertEqual(token['scope'], 'foo bar')

    def test_invalid_scope(self):
        self.mock_validator.get_original_scopes.return_value = ['baz']
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertEqual(token['error'], 'invalid_scope')
        self.assertEqual(status_code, 401)

    def test_invalid_token(self):
        self.mock_validator.validate_refresh_token.return_value = False
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertEqual(token['error'], 'invalid_grant')
        self.assertEqual(status_code, 400)

    def test_invalid_client(self):
        self.mock_validator.authenticate_client.return_value = False
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertEqual(token['error'], 'invalid_client')
        self.assertEqual(status_code, 401)
