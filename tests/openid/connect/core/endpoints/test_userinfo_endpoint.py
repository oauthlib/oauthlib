# -*- coding: utf-8 -*-
import json
from unittest import mock

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.openid import RequestValidator, UserInfoEndpoint

from tests.unittest import TestCase


def set_scopes_valid(token, scopes, request):
    request.scopes = ["openid", "bar"]
    return True


class UserInfoEndpointTest(TestCase):
    def setUp(self):
        self.claims = {
            "sub": "john",
            "fruit": "banana"
        }
        # Can't use MagicMock/wraps below.
        # Triggers error when endpoint copies to self.bearer.request_validator
        self.validator = RequestValidator()
        self.validator.validate_bearer_token = mock.AsyncMock()
        self.validator.validate_bearer_token.side_effect = set_scopes_valid
        self.validator.get_userinfo_claims = mock.AsyncMock()
        self.validator.get_userinfo_claims.return_value = self.claims
        self.endpoint = UserInfoEndpoint(self.validator)

        self.uri = 'should_not_matter'
        self.headers = {
            'Authorization': 'Bearer eyJxx'
        }

    async def test_userinfo_no_auth(self):
        await self.endpoint.create_userinfo_response(self.uri)

    async def test_userinfo_wrong_auth(self):
        self.headers['Authorization'] = 'Basic foifoifoi'
        await self.endpoint.create_userinfo_response(self.uri, headers=self.headers)

    async def test_userinfo_token_expired(self):
        self.validator.validate_bearer_token.return_value = False
        await self.endpoint.create_userinfo_response(self.uri, headers=self.headers)

    async def test_userinfo_token_no_openid_scope(self):
        def set_scopes_invalid(token, scopes, request):
            request.scopes = ["foo", "bar"]
            return True
        self.validator.validate_bearer_token.side_effect = set_scopes_invalid
        with self.assertRaises(errors.InsufficientScopeError) as context:
            await self.endpoint.create_userinfo_response(self.uri)

    async def test_userinfo_json_response(self):
        h, b, s = await self.endpoint.create_userinfo_response(self.uri)
        self.assertEqual(s, 200)
        body_json = json.loads(b)
        self.assertEqual(self.claims, body_json)
        self.assertEqual("application/json", h['Content-Type'])

    async def test_userinfo_jwt_response(self):
        self.validator.get_userinfo_claims.return_value = "eyJzzzzz"
        h, b, s = await self.endpoint.create_userinfo_response(self.uri)
        self.assertEqual(s, 200)
        self.assertEqual(b, "eyJzzzzz")
        self.assertEqual("application/jwt", h['Content-Type'])
