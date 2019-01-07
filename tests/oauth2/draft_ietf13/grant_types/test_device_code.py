# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import json

import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.draft_ietf13.grant_types import DeviceCodeGrant
from oauthlib.oauth2.draft_ietf13.tokens import DeviceToken

from ....unittest import TestCase


class DeviceCodeGrantTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.expires_in = 1800
        self.request.client = 'batman'
        self.request.client_id = 'abcdef'
        self.request.device_code = '1234'
        self.request.response_type = 'code'
        self.request.grant_type = 'urn:ietf:params:oauth:grant-type:device_code'

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = self.set_client
        
        self.auth = DeviceCodeGrant(request_validator=self.mock_validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        
        return True

    def setup_validators(self):
        self.authval1, self.authval2 = mock.Mock(), mock.Mock()
        self.authval1.return_value = {}
        self.authval2.return_value = {}
        self.tknval1, self.tknval2 = mock.Mock(), mock.Mock()
        self.tknval1.return_value = None
        self.tknval2.return_value = None

        self.auth.custom_validators.pre_token.append(self.tknval1)
        self.auth.custom_validators.post_token.append(self.tknval2)
        self.auth.custom_validators.pre_auth.append(self.authval1)
        self.auth.custom_validators.post_auth.append(self.authval2)

    def test_custom_auth_validators(self):
        self.setup_validators()

        device = DeviceToken(self.mock_validator)
        self.auth.create_authorization_response(self.request, device)
        self.assertTrue(self.authval1.called)
        self.assertTrue(self.authval2.called)
        self.assertFalse(self.tknval1.called)
        self.assertFalse(self.tknval2.called)

    def test_custom_token_validators(self):
        self.setup_validators()

        device = DeviceToken(self.mock_validator)
        self.auth.create_token_response(self.request, device)
        self.assertTrue(self.tknval1.called)
        self.assertTrue(self.tknval2.called)
        self.assertFalse(self.authval1.called)
        self.assertFalse(self.authval2.called)

    def test_create_authorization_grant(self):
        device = DeviceToken(self.mock_validator)
        h, b, s = self.auth.create_authorization_response(self.request, device)

        self.assertIn('user_code', b)
        self.assertIn('device_code', b)
        self.assertIn('expires_in', b)
        self.assertIn('interval', b)
        self.assertIn('verification_uri', b)
        self.assertIn('verification_uri_complete', b)

        self.assertTrue(self.mock_validator.validate_scopes.called)

    def test_create_authorization_grant_no_scopes(self):
        device = DeviceToken(self.mock_validator)
        self.request.scopes = []
        self.auth.create_authorization_response(self.request, device)

    # def test_create_token_response(self):
    #     bearer = BearerToken(self.mock_validator)

    #     h, token, s = self.auth.create_token_response(self.request, bearer)
    #     token = json.loads(token)
    #     self.assertEqual(self.mock_validator.save_token.call_count, 1)
    #     self.assertIn('access_token', token)
    #     self.assertIn('refresh_token', token)
    #     self.assertIn('expires_in', token)
    #     self.assertIn('scope', token)
    #     self.assertTrue(self.mock_validator.client_authentication_required.called)
    #     self.assertTrue(self.mock_validator.authenticate_client.called)
    #     self.assertTrue(self.mock_validator.validate_code.called)
    #     self.assertTrue(self.mock_validator.confirm_redirect_uri.called)
    #     self.assertTrue(self.mock_validator.validate_grant_type.called)
    #     self.assertTrue(self.mock_validator.invalidate_authorization_code.called)

    # def test_create_token_response_without_refresh_token(self):
    #     self.auth.refresh_token = False  # Not to issue refresh token.

    #     bearer = BearerToken(self.mock_validator)
    #     h, token, s = self.auth.create_token_response(self.request, bearer)
    #     token = json.loads(token)
    #     self.assertEqual(self.mock_validator.save_token.call_count, 1)
    #     self.assertIn('access_token', token)
    #     self.assertNotIn('refresh_token', token)
    #     self.assertIn('expires_in', token)
    #     self.assertIn('scope', token)
    #     self.assertTrue(self.mock_validator.client_authentication_required.called)
    #     self.assertTrue(self.mock_validator.authenticate_client.called)
    #     self.assertTrue(self.mock_validator.validate_code.called)
    #     self.assertTrue(self.mock_validator.validate_grant_type.called)
    #     self.assertTrue(self.mock_validator.invalidate_authorization_code.called)

    def test_invalid_request(self):
        del self.request.device_code
        self.assertRaises(errors.InvalidRequestError, self.auth.validate_token_request,
                          self.request)

    def test_invalid_request_duplicates(self):
        request = mock.MagicMock(wraps=self.request)
        request.grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
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
        request.grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
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

        self.assertRaises(errors.InvalidClientError,
                          self.auth.validate_token_request, self.request)
