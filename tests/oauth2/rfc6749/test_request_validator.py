# -*- coding: utf-8 -*-
from oauthlib.oauth2 import RequestValidator

from tests.unittest import TestCase


class RequestValidatorTest(TestCase):

    async def test_method_contracts(self):
        v = RequestValidator()
        await self.assertRaisesAsync(NotImplementedError, v.authenticate_client, 'r')
        await self.assertRaisesAsync(NotImplementedError, v.authenticate_client_id,
                'client_id', 'r')
        await self.assertRaisesAsync(NotImplementedError, v.confirm_redirect_uri,
                'client_id', 'code', 'redirect_uri', 'client', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.get_default_redirect_uri,
                'client_id', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.get_default_scopes,
                'client_id', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.get_original_scopes,
                'refresh_token', 'request')
        self.assertFalse(await v.is_within_original_scope(
                ['scope'], 'refresh_token', 'request'))
        await self.assertRaisesAsync(NotImplementedError, v.invalidate_authorization_code,
                'client_id', 'code', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.save_authorization_code,
                'client_id', 'code', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.save_bearer_token,
                'token', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_bearer_token,
                'token', 'scopes', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_client_id,
                'client_id', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_code,
                'client_id', 'code', 'client', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_grant_type,
                'client_id', 'grant_type', 'client', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_redirect_uri,
                'client_id', 'redirect_uri', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_refresh_token,
                'refresh_token', 'client', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_response_type,
                'client_id', 'response_type', 'client', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_scopes,
                'client_id', 'scopes', 'client', 'request')
        await self.assertRaisesAsync(NotImplementedError, v.validate_user,
                'username', 'password', 'client', 'request')
        self.assertTrue(await v.client_authentication_required('r'))
        self.assertFalse(
            await v.is_origin_allowed('client_id', 'https://foo.bar', 'r')
        )
