# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from ...unittest import TestCase

import json
import mock
from oauthlib import common
from oauthlib.common import Request
from oauthlib.oauth2.draft25.errors import UnsupportedGrantTypeError
from oauthlib.oauth2.draft25.errors import InvalidRequestError
from oauthlib.oauth2.draft25.errors import UnauthorizedClientError
from oauthlib.oauth2.draft25.errors import InvalidGrantError
from oauthlib.oauth2.draft25.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.draft25.grant_types import ImplicitGrant
from oauthlib.oauth2.draft25.grant_types import ResourceOwnerPasswordCredentialsGrant
from oauthlib.oauth2.draft25.grant_types import ClientCredentialsGrant
from oauthlib.oauth2.draft25.tokens import BearerToken


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
        self.auth = AuthorizationCodeGrant(request_validator=self.mock_validator)

    def test_create_authorization_grant(self):
        grant = self.auth.create_authorization_code(self.request)
        self.assertIn('code', grant)

        grant = self.auth.create_authorization_code(self.request_state)
        self.assertIn('code', grant)
        self.assertIn('state', grant)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        u, h, token, s = self.auth.create_token_response(self.request, bearer)
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

        mock_validator.validate_client = mock.MagicMock(return_value=False)
        request.code = 'waffles'
        request.client = 'batman'
        self.assertRaises(UnauthorizedClientError,
                auth.validate_token_request, request)

        mock_validator.validate_client = mock.MagicMock(return_value=True)
        mock_validator.validate_code = mock.MagicMock(return_value=False)
        self.assertRaises(InvalidGrantError,
                auth.validate_token_request, request)


class ImplicitGrantTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.client = 'batman'
        self.request.client_id = 'abcdef'
        self.request.response_type = 'token'
        self.request.state = 'xyz'
        self.request.redirect_uri = 'https://b.c/p'

        self.mock_validator = mock.MagicMock()
        self.auth = ImplicitGrant(request_validator=self.mock_validator)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        orig_generate_token = common.generate_token
        self.addCleanup(setattr, common, 'generate_token', orig_generate_token)
        common.generate_token = lambda *args, **kwargs: '1234'
        uri, headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        correct_uri = 'https://b.c/p#access_token=1234&token_type=Bearer&expires_in=3600&state=xyz&scope=hello+world'
        self.assertURLEqual(uri, correct_uri, parse_fragment=True)

    def test_error_response(self):
        pass


class ResourceOwnerPasswordCredentialsGrantTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'password'
        self.request.username = 'john'
        self.request.password = 'doe'
        self.request.client = 'mock authenticated'
        self.request.scopes = ('mocked', 'scopes')
        self.mock_validator = mock.MagicMock()
        self.auth = ResourceOwnerPasswordCredentialsGrant(
                request_validator=self.mock_validator)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        uri, headers, body, status_code = self.auth.create_token_response(
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
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'client_credentials'
        self.request.client = 'mock authenticated'
        self.request.scopes = ('mocked', 'scopes')
        self.mock_validator = mock.MagicMock()
        self.auth = ClientCredentialsGrant(
                request_validator=self.mock_validator)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        uri, headers, body, status_code = self.auth.create_token_response(
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
