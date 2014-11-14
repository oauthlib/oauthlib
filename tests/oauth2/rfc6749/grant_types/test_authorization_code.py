# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from ....unittest import TestCase

import json
import mock
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.tokens import BearerToken


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
        self.request.redirect_uri = 'https://a.b/cb'

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = self.set_client
        self.auth = AuthorizationCodeGrant(request_validator=self.mock_validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def test_create_authorization_grant(self):
        bearer = BearerToken(self.mock_validator)
        h, b, s = self.auth.create_authorization_response(self.request, bearer)
        grant = dict(Request(h['Location']).uri_query_params)
        self.assertIn('code', grant)
        self.assertTrue(self.mock_validator.validate_redirect_uri.called)
        self.assertTrue(self.mock_validator.validate_response_type.called)
        self.assertTrue(self.mock_validator.validate_scopes.called)

    def test_create_authorization_grant_state(self):
        self.request.state = 'abc'
        self.request.redirect_uri = None
        self.mock_validator.get_default_redirect_uri.return_value = 'https://a.b/cb'
        bearer = BearerToken(self.mock_validator)
        h, b, s = self.auth.create_authorization_response(self.request, bearer)
        grant = dict(Request(h['Location']).uri_query_params)
        self.assertIn('code', grant)
        self.assertIn('state', grant)
        self.assertFalse(self.mock_validator.validate_redirect_uri.called)
        self.assertTrue(self.mock_validator.get_default_redirect_uri.called)
        self.assertTrue(self.mock_validator.validate_response_type.called)
        self.assertTrue(self.mock_validator.validate_scopes.called)

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        h, token, s = self.auth.create_token_response(self.request, bearer)
        token = json.loads(token)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertIn('expires_in', token)
        self.assertIn('scope', token)
        self.assertTrue(self.mock_validator.client_authentication_required.called)
        self.assertTrue(self.mock_validator.authenticate_client.called)
        self.assertTrue(self.mock_validator.validate_code.called)
        self.assertTrue(self.mock_validator.confirm_redirect_uri.called)
        self.assertTrue(self.mock_validator.validate_grant_type.called)
        self.assertTrue(self.mock_validator.invalidate_authorization_code.called)

    def test_invalid_request(self):
        del self.request.code
        self.assertRaises(errors.InvalidRequestError, self.auth.validate_token_request,
                          self.request)

    def test_invalid_request_duplicates(self):
        request = mock.MagicMock(wraps=self.request)
        request.grant_type = 'authorization_code'
        request.duplicate_params = ['client_id']
        self.assertRaises(errors.InvalidRequestError, self.auth.validate_token_request,
                          request)

    def test_authentication_required(self):
        """
        ensure client_authentication_required() is properly called
        """
        self.auth.validate_token_request(self.request)
        self.mock_validator.client_authentication_required.assert_called_once_with(self.request)

    def test_authenticate_client(self):
        self.mock_validator.authenticate_client.side_effect = None
        self.mock_validator.authenticate_client.return_value = False
        self.assertRaises(errors.InvalidClientError, self.auth.validate_token_request,
                          self.request)

    def test_client_id_missing(self):
        self.mock_validator.authenticate_client.side_effect = None
        request = mock.MagicMock(wraps=self.request)
        request.grant_type = 'authorization_code'
        del request.client.client_id
        self.assertRaises(NotImplementedError, self.auth.validate_token_request,
                          request)

    def test_invalid_grant(self):
        self.request.client = 'batman'
        self.mock_validator.authenticate_client = self.set_client
        self.mock_validator.validate_code.return_value = False
        self.assertRaises(errors.InvalidGrantError,
                          self.auth.validate_token_request, self.request)

    def test_invalid_grant_type(self):
        self.request.grant_type = 'foo'
        self.assertRaises(errors.UnsupportedGrantTypeError,
                          self.auth.validate_token_request, self.request)

    def test_authenticate_client_id(self):
        self.mock_validator.client_authentication_required.return_value = False
        self.mock_validator.authenticate_client_id.return_value = False
        self.request.state = 'abc'
        self.assertRaises(errors.InvalidClientError,
                          self.auth.validate_token_request, self.request)

    def test_invalid_redirect_uri(self):
        self.mock_validator.confirm_redirect_uri.return_value = False
        self.assertRaises(errors.AccessDeniedError,
                          self.auth.validate_token_request, self.request)
