# -*- coding: utf-8 -*-
from oauthlib.openid import RequestValidator

from tests.unittest import TestCase


class RequestValidatorTest(TestCase):

    async def test_method_contracts(self):
        v = RequestValidator()
        await self.assertRaisesAsync(
            NotImplementedError,
            v.get_authorization_code_scopes,
            'client_id', 'code', 'redirect_uri', 'request'
        )
        await self.assertRaisesAsync(
            NotImplementedError,
            v.get_jwt_bearer_token,
            'token', 'token_handler', 'request'
        )
        await self.assertRaisesAsync(
            NotImplementedError,
            v.finalize_id_token,
            'id_token', 'token', 'token_handler', 'request'
        )
        await self.assertRaisesAsync(
            NotImplementedError,
            v.validate_jwt_bearer_token,
            'token', 'scopes', 'request'
        )
        await self.assertRaisesAsync(
            NotImplementedError,
            v.validate_id_token,
            'token', 'scopes', 'request'
        )
        await self.assertRaisesAsync(
            NotImplementedError,
            v.validate_silent_authorization,
            'request'
        )
        await self.assertRaisesAsync(
            NotImplementedError,
            v.validate_silent_login,
            'request'
        )
        await self.assertRaisesAsync(
            NotImplementedError,
            v.validate_user_match,
            'id_token_hint', 'scopes', 'claims', 'request'
        )
