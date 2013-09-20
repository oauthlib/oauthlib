# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from ....unittest import TestCase

import json
import mock
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.grant_types import RefreshTokenGrant
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc6749.errors import (UnsupportedGrantTypeError,
                                            InvalidClientError,
                                            InvalidRequestError,
                                            InvalidGrantError,
                                            InvalidScopeError)


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

    def test_validate_token_request(self):
        # ensure client_authentication_required() is properly called
        self.mock_validator.authenticate_client.return_value = False
        self.mock_validator.authenticate_client_id.return_value = False
        self.request.code = 'waffles'
        self.assertRaises(InvalidClientError, self.auth.validate_token_request,
                          self.request)
        args, _ = self.mock_validator.client_authentication_required.call_args_list[0]
        self.assertEqual(args, (self.request,))
        # fail with wrong grant type
        self.request.grant_type = 'wrong_type'
        self.assertRaises(UnsupportedGrantTypeError,
                          self.auth.validate_token_request, self.request)
        # fail for not providing a refresh token
        self.request.grant_type = 'refresh_token'
        del self.request.refresh_token
        self.assertRaises(InvalidRequestError,
                          self.auth.validate_token_request, self.request)
        # fail client_id authentication
        self.mock_validator.client_authentication_required.return_value = False
        self.request.refresh_token = mock.MagicMock()
        self.mock_validator.authenticate_client_id.return_value = False
        self.assertRaises(InvalidClientError,
                          self.auth.validate_token_request, self.request)
        # invalid refresh token
        self.mock_validator.authenticate_client_id.return_value = True
        self.mock_validator.validate_refresh_token.return_value = False
        self.assertRaises(InvalidGrantError,
                          self.auth.validate_token_request, self.request)
        # fail scope error
        self.mock_validator.validate_refresh_token.return_value = True
        self.assertRaises(InvalidScopeError,
                          self.auth.validate_token_request, self.request)
        # all ok
        self.request.scope = 'foo bar'
        self.mock_validator.get_original_scopes = mock.Mock()
        self.mock_validator.get_original_scopes.return_value = 'foo bar baz'
        self.auth.validate_token_request(self.request)
        self.assertEqual(self.request.scopes, self.request.scope.split())
        # all ok but without request.scope
        del self.request.scope
        self.auth.validate_token_request(self.request)
        self.assertEqual(self.request.scopes, 'foo bar baz'.split())
