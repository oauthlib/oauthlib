# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from ...unittest import TestCase
import json
import mock

from oauthlib.oauth2 import draft25
from oauthlib.oauth2.draft25 import grant_types, tokens, errors


class AuthorizationEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = grant_types.AuthorizationCodeGrant(
                request_validator=self.mock_validator)
        auth_code.save_authorization_code = mock.MagicMock()
        implicit = grant_types.ImplicitGrant(
                request_validator=self.mock_validator)
        implicit.save_token = mock.MagicMock()
        response_types = {
                'code': auth_code,
                'token': implicit,
        }

        token = tokens.BearerToken(self.mock_validator)
        self.endpoint = draft25.AuthorizationEndpoint(
                default_response_type='code',
                default_token=token,
                response_types=response_types)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        uri = 'http://i.b/l?response_type=code&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        uri, headers, body, status_code = self.endpoint.create_authorization_response(uri)
        self.assertURLEqual(uri, 'http://back.to/me?code=abc&state=xyz')

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_implicit_grant(self):
        uri = 'http://i.b/l?response_type=token&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        uri, headers, body, status_code = self.endpoint.create_authorization_response(uri)
        self.assertURLEqual(uri, 'http://back.to/me#access_token=abc&expires_in=3600&token_type=Bearer&state=xyz', parse_fragment=True)

    def test_missing_type(self):
        uri = 'http://i.b/l?client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
                side_effect=errors.InvalidRequestError())
        uri, headers, body, status_code = self.endpoint.create_authorization_response(uri)
        self.assertURLEqual(uri, 'http://back.to/me?error=invalid_request&error_description=Missing+response_type+parameter.')

    def test_invalid_type(self):
        uri = 'http://i.b/l?response_type=invalid&client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
                side_effect=errors.UnsupportedResponseTypeError())
        uri, headers, body, status_code = self.endpoint.create_authorization_response(uri)
        self.assertURLEqual(uri, 'http://back.to/me?error=unsupported_response_type')


class TokenEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = grant_types.AuthorizationCodeGrant(
                request_validator=self.mock_validator)
        password = grant_types.ResourceOwnerPasswordCredentialsGrant(
                request_validator=self.mock_validator)
        client = grant_types.ClientCredentialsGrant(
                request_validator=self.mock_validator)
        supported_types = {
                'authorization_code': auth_code,
                'password': password,
                'client_credentials': client,
        }
        token = tokens.BearerToken(self.mock_validator)
        self.endpoint = draft25.TokenEndpoint('authorization_code',
                default_token_type=token, grant_types=supported_types)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        body = 'grant_type=authorization_code&code=abc&scope=all+of+them&state=xyz'
        uri, headers, body, status_code = self.endpoint.create_token_response(
                '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': 3600,
            'access_token': 'abc',
            'refresh_token': 'abc',
            'state': 'xyz'
        }
        self.assertEqual(json.loads(body), token)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_password_grant(self):
        body = 'grant_type=password&username=a&password=hello&scope=all+of+them'
        uri, headers, body, status_code = self.endpoint.create_token_response(
                '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': 3600,
            'access_token': 'abc',
            'refresh_token': 'abc'
        }
        self.assertEqual(json.loads(body), token)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_client_grant(self):
        body = 'grant_type=client_credentials&scope=all+of+them'
        uri, headers, body, status_code = self.endpoint.create_token_response(
                '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': 3600,
            'access_token': 'abc',
        }
        self.assertEqual(json.loads(body), token)

    def test_missing_type(self):
        _, _, body, _ = self.endpoint.create_token_response('', body='')
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)

    def test_invalid_type(self):
        body = 'grant_type=invalid'
        _, _, body, _ = self.endpoint.create_token_response('', body=body)
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)


class ResourceEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        token = tokens.BearerToken(request_validator=self.mock_validator)
        self.endpoint = draft25.ResourceEndpoint(default_token='Bearer',
                token_types={'Bearer': token})

    def test_defaults(self):
        uri = 'http://a.b/path?some=query'
        self.mock_validator.validate_bearer_token.return_value = False
        valid, request = self.endpoint.verify_request(uri)
        self.assertFalse(valid)
        self.assertEqual(request.token_type, 'Bearer')
