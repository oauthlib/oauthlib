# -*- coding: utf-8 -*-
import json
from unittest import mock

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.endpoints.authorization import (
    AuthorizationEndpoint,
)
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.openid.connect.core.grant_types.authorization_code import (
    AuthorizationCodeGrant,
)
from oauthlib.openid.connect.core.grant_types.hybrid import HybridGrant
from oauthlib.openid.connect.core.grant_types.implicit import ImplicitGrant

from tests.unittest import TestCase


class AuthorizationEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.mock_validator.get_code_challenge.return_value = None
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = AuthorizationCodeGrant(request_validator=self.mock_validator)
        auth_code.save_authorization_code = mock.MagicMock()
        implicit = ImplicitGrant(
            request_validator=self.mock_validator)
        implicit.save_token = mock.MagicMock()
        hybrid = HybridGrant(self.mock_validator)

        response_types = {
            'code': auth_code,
            'token': implicit,
            'id_token': implicit,
            'id_token token': implicit,
            'code token': hybrid,
            'code id_token': hybrid,
            'code token id_token': hybrid,
            'none': auth_code
        }
        self.expires_in = 1800
        token = BearerToken(
            self.mock_validator,
            expires_in=self.expires_in
        )
        self.endpoint = AuthorizationEndpoint(
            default_response_type='code',
            default_token_type=token,
            response_types=response_types
        )

    # TODO: Add hybrid grant test

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        uri = 'http://i.b/l?response_type=code&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?code=abc&state=xyz')

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_implicit_grant(self):
        uri = 'http://i.b/l?response_type=token&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me#access_token=abc&expires_in=' + str(self.expires_in) + '&token_type=Bearer&state=xyz&scope=all+of+them', parse_fragment=True)

    def test_none_grant(self):
        uri = 'http://i.b/l?response_type=none&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, body, status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?state=xyz', parse_fragment=True)
        self.assertIsNone(body)
        self.assertEqual(status_code, 302)

        # and without the state parameter
        uri = 'http://i.b/l?response_type=none&client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, body, status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me', parse_fragment=True)
        self.assertIsNone(body)
        self.assertEqual(status_code, 302)

    def test_missing_type(self):
        uri = 'http://i.b/l?client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
            side_effect=errors.InvalidRequestError())
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?error=invalid_request&error_description=Missing+response_type+parameter.')

    def test_invalid_type(self):
        uri = 'http://i.b/l?response_type=invalid&client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
            side_effect=errors.UnsupportedResponseTypeError())
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?error=unsupported_response_type')

    def test_reordered_response_type_uses_registered_handler(self):
        # RFC 6749 section 3.1.1: the order of response_type values does not matter.
        for response_type in ('id_token+code', 'id_token+token+code', 'token+id_token'):
            uri = 'http://i.b/l?response_type=%s&client_id=me&scope=openid' % response_type
            uri += '&state=xyz&nonce=n&redirect_uri=http%3A%2F%2Fback.to%2Fme'
            expected = {
                'id_token+code': ('code id_token', HybridGrant),
                'id_token+token+code': ('code token id_token', HybridGrant),
                'token+id_token': ('id_token token', ImplicitGrant),
            }[response_type]
            with mock.patch.object(expected[1], 'validate_authorization_request',
                                   autospec=True, return_value=([], {})) as validate:
                self.endpoint.validate_authorization_request(uri)
            request = validate.call_args[0][1]
            self.assertEqual(request.response_type, expected[0])

    def test_reordered_hybrid_response_type_requires_nonce(self):
        uri = 'http://i.b/l?response_type=id_token+code&client_id=me&scope=openid'
        uri += '&state=xyz&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['openid'])
        self.assertIn('Location', headers)
        self.assertIn('error=invalid_request', headers['Location'])
        self.assertIn('nonce', headers['Location'])

    def test_response_type_with_repeated_or_empty_values_is_not_rewritten(self):
        for response_type in ('code code', 'code  id_token', 'id_token code code', 'code bogus'):
            request = mock.MagicMock(response_type=response_type)
            self.endpoint._canonicalize_response_type(request)
            self.assertEqual(request.response_type, response_type)


class TokenEndpointTest(TestCase):

    def setUp(self):
        def set_user(request):
            request.user = mock.MagicMock()
            request.client = mock.MagicMock()
            request.client.client_id = 'mocked_client_id'
            return True

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = set_user
        self.mock_validator.get_code_challenge.return_value = None
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = AuthorizationCodeGrant(
            request_validator=self.mock_validator)
        supported_types = {
            'authorization_code': auth_code,
        }
        self.expires_in = 1800
        token = BearerToken(
            self.mock_validator,
            expires_in=self.expires_in
        )
        self.endpoint = TokenEndpoint(
            'authorization_code',
            default_token_type=token,
            grant_types=supported_types
        )

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        body = 'grant_type=authorization_code&code=abc&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc',
            'scope': 'all of them'
        }
        self.assertEqual(json.loads(body), token)

        body = 'grant_type=authorization_code&code=abc'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc'
        }
        self.assertEqual(json.loads(body), token)

        # ignore useless fields
        body = 'grant_type=authorization_code&code=abc&state=foobar'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
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
