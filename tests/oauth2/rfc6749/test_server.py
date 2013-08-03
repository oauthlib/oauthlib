# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from ...unittest import TestCase
import json
import mock

from oauthlib.oauth2.rfc6749.endpoints.authorization import AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.endpoints.resource import ResourceEndpoint
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.grant_types import ImplicitGrant
from oauthlib.oauth2.rfc6749.grant_types import ResourceOwnerPasswordCredentialsGrant
from oauthlib.oauth2.rfc6749.grant_types import ClientCredentialsGrant
from oauthlib.oauth2.rfc6749 import tokens, errors


class AuthorizationEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = AuthorizationCodeGrant(
                request_validator=self.mock_validator)
        auth_code.save_authorization_code = mock.MagicMock()
        implicit = ImplicitGrant(
                request_validator=self.mock_validator)
        implicit.save_token = mock.MagicMock()
        response_types = {
                'code': auth_code,
                'token': implicit,
        }
        self.expires_in = 1800
        token = tokens.BearerToken(self.mock_validator,
                expires_in=self.expires_in)
        self.endpoint = AuthorizationEndpoint(
                default_response_type='code',
                default_token_type=token,
                response_types=response_types)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        uri = 'http://i.b/l?response_type=code&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, body, status_code = self.endpoint.create_authorization_response(
                uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?code=abc&state=xyz')

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_implicit_grant(self):
        uri = 'http://i.b/l?response_type=token&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, body, status_code = self.endpoint.create_authorization_response(
                uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me#access_token=abc&expires_in=' + str(self.expires_in) + '&token_type=Bearer&state=xyz&scope=all+of+them', parse_fragment=True)

    def test_missing_type(self):
        uri = 'http://i.b/l?client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
                side_effect=errors.InvalidRequestError())
        headers, body, status_code = self.endpoint.create_authorization_response(
                uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?error=invalid_request&error_description=Missing+response_type+parameter.')

    def test_invalid_type(self):
        uri = 'http://i.b/l?response_type=invalid&client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
                side_effect=errors.UnsupportedResponseTypeError())
        headers, body, status_code = self.endpoint.create_authorization_response(
                uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?error=unsupported_response_type')


class TokenEndpointTest(TestCase):

    def setUp(self):
        def set_user(request):
            request.user = mock.MagicMock()
            request.client = mock.MagicMock()
            request.client.client_id = 'mocked_client_id'
            return True

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = set_user
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = AuthorizationCodeGrant(
                request_validator=self.mock_validator)
        password = ResourceOwnerPasswordCredentialsGrant(
                request_validator=self.mock_validator)
        client = ClientCredentialsGrant(
                request_validator=self.mock_validator)
        supported_types = {
                'authorization_code': auth_code,
                'password': password,
                'client_credentials': client,
        }
        self.expires_in = 1800
        token = tokens.BearerToken(self.mock_validator,
                expires_in=self.expires_in)
        self.endpoint = TokenEndpoint('authorization_code',
                default_token_type=token, grant_types=supported_types)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        body = 'grant_type=authorization_code&code=abc&scope=all+of+them&state=xyz'
        headers, body, status_code = self.endpoint.create_token_response(
                '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc',
            'state': 'xyz'
        }
        self.assertEqual(json.loads(body), token)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_password_grant(self):
        body = 'grant_type=password&username=a&password=hello&scope=all+of+them'
        headers, body, status_code = self.endpoint.create_token_response(
                '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc',
            'scope': 'all of them',
        }
        self.assertEqual(json.loads(body), token)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_client_grant(self):
        body = 'grant_type=client_credentials&scope=all+of+them'
        headers, body, status_code = self.endpoint.create_token_response(
                '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'scope': 'all of them',
        }
        self.assertEqual(json.loads(body), token)

    def test_missing_type(self):
        _, body, _ = self.endpoint.create_token_response('', body='')
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)

    def test_invalid_type(self):
        body = 'grant_type=invalid'
        _, body, _ = self.endpoint.create_token_response('', body=body)
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)


class ResourceEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        token = tokens.BearerToken(request_validator=self.mock_validator)
        self.endpoint = ResourceEndpoint(default_token='Bearer',
                token_types={'Bearer': token})

    def test_defaults(self):
        uri = 'http://a.b/path?some=query'
        self.mock_validator.validate_bearer_token.return_value = False
        valid, request = self.endpoint.verify_request(uri)
        self.assertFalse(valid)
        self.assertEqual(request.token_type, 'Bearer')
