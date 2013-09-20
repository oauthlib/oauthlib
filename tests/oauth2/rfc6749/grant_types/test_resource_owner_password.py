# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from ....unittest import TestCase

import json
import mock
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.grant_types import ResourceOwnerPasswordCredentialsGrant
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator
from oauthlib.oauth2.rfc6749.errors import (InvalidRequestError,
                                            UnsupportedGrantTypeError,
                                            InvalidGrantError,
                                            InvalidClientError)


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

    def set_client(self, request, *args, **kwargs):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
                self.request, bearer)
        token = json.loads(body)
        self.assertIn('access_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)
        self.assertIn('refresh_token', token)
        # ensure client_authentication_required() is properly called
        args, _ = self.mock_validator.client_authentication_required.call_args_list[0]
        self.assertEqual(args, (self.request,))
        # fail client authentication
        self.mock_validator.validate_user = mock.Mock()
        self.mock_validator.validate_user.return_value = True
        self.mock_validator.authenticate_client = mock.Mock()
        self.mock_validator.authenticate_client.return_value = False
        status_code = self.auth.create_token_response(self.request, bearer)[2]
        self.assertEqual(status_code, 400)
        # mock client_authentication_required() returning False then fail
        self.mock_validator.client_authentication_required = mock.Mock()
        self.mock_validator.client_authentication_required.return_value = False
        self.mock_validator.authenticate_client_id = mock.Mock()
        self.mock_validator.authenticate_client_id.return_value = False
        status_code = self.auth.create_token_response(self.request, bearer)[2]
        self.assertEqual(status_code, 400)

    def test_error_response(self):
        pass

    def test_scopes(self):
        pass

    def test_validate_token_request(self):
        mock_validator = mock.MagicMock(spec=RequestValidator)
        mock_validator.validate_user = self.set_client

        auth = ResourceOwnerPasswordCredentialsGrant(
            request_validator=mock_validator)
        request = Request('http://a.b/path')
        # no params
        self.assertRaises(InvalidRequestError, auth.validate_token_request,
                          request)
        # right params but with duplicates
        request = Request('http://a.b/path/?scope=one', body='scope=another')
        request.client_id = 'client_id'
        request.username = 'user'
        request.password = 'pass'
        request.grant_type = 'password'
        self.assertRaises(InvalidRequestError, auth.validate_token_request,
                          request)
        # wrong grant type
        request = Request('http://a.b/path')
        request.client_id = 'client_id'
        request.username = 'user'
        request.password = 'pass'
        request.grant_type = 'foo'
        self.assertRaises(UnsupportedGrantTypeError,
                          auth.validate_token_request, request)
        # wrong user
        request.grant_type = 'password'
        mock_validator.validate_user = mock.Mock()
        mock_validator.validate_user.return_value = False
        self.assertRaises(InvalidGrantError, auth.validate_token_request,
                          request)
        # user ok but request.client.client_id missing
        mock_validator.validate_user.return_value = True
        request.client = mock.Mock()
        del request.client.client_id
        self.assertRaises(NotImplementedError, auth.validate_token_request,
                          request)
        # everything fine
        request.client = mock.Mock()
        mock_validator.validate_grant_type.return_value = True
        auth.validate_token_request(request)
