"""Ensure that the server correctly uses the OIDC flavor of
the Refresh token grant type when appropriate.

When the OpenID scope is provided, the refresh token response
should include a fresh ID token.
"""
import json
from unittest import mock

from oauthlib.openid import RequestValidator
from oauthlib.openid.connect.core.endpoints.pre_configured import Server

from tests.unittest import TestCase


class TestRefreshToken(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_id_token.return_value='id_token'

        self.server = Server(self.validator)

    def test_refresh_token_with_openid(self):
        body = 'scope=openid+test_scope&grant_type=refresh_token&refresh_token=abc'
        h, b, s = self.server.create_token_response('', body=body)
        self.assertIn('id_token', json.loads(b))

    def test_refresh_token_no_openid(self):
        body = 'scope=test_scope&grant_type=refresh_token&refresh_token=abc'
        h, b, s = self.server.create_token_response('', body=body)
        self.assertNotIn('id_token', json.loads(b))
