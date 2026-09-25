# -*- coding: utf-8 -*-
import time
from unittest import mock

from oauthlib.common import Request
from oauthlib.openid.connect.core.grant_types.base import GrantTypeBase

from tests.unittest import TestCase, validator_mock


class GrantBase(GrantTypeBase):
    """Class to test GrantTypeBase"""
    def __init__(self, request_validator=None, **kwargs):
        self.request_validator = request_validator


class IDTokenTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'openid')
        self.request.expires_in = 1800
        self.request.client_id = 'abcdef'
        self.request.code = '1234'
        self.request.response_type = 'id_token'
        self.request.grant_type = 'authorization_code'
        self.request.redirect_uri = 'https://a.b/cb'
        self.request.state = 'abc'
        self.request.nonce = None

        self.mock_validator = validator_mock()
        self.mock_validator.get_id_token.return_value = None
        self.mock_validator.finalize_id_token.return_value = "eyJ.body.signature"
        self.token = {}

        self.grant = GrantBase(request_validator=self.mock_validator)

        self.url_query = 'https://a.b/cb?code=abc&state=abc'
        self.url_fragment = 'https://a.b/cb#code=abc&state=abc'

    def test_id_token_hash(self):
        self.assertEqual(self.grant.id_token_hash(
            "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk",
        ), "LDktKdoQak3Pk0cnXxCltA", "hash differs from RFC")

    async def test_get_id_token_no_openid(self):
        self.request.scopes = ('hello')
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request)
        self.assertNotIn("id_token", token)

        self.request.scopes = None
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request)
        self.assertNotIn("id_token", token)

        self.request.scopes = ()
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request)
        self.assertNotIn("id_token", token)

    async def test_get_id_token(self):
        self.mock_validator.get_id_token.return_value = "toto"
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request)
        self.assertIn("id_token", token)
        self.assertEqual(token["id_token"], "toto")

    async def test_finalize_id_token(self):
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request)
        self.assertIn("id_token", token)
        self.assertEqual(token["id_token"], "eyJ.body.signature")
        id_token = self.mock_validator.finalize_id_token.call_args[0][0]
        self.assertEqual(id_token['aud'], 'abcdef')
        self.assertGreaterEqual(int(time.time()), id_token['iat'])

    async def test_finalize_id_token_with_nonce(self):
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request, "my_nonce")
        self.assertIn("id_token", token)
        self.assertEqual(token["id_token"], "eyJ.body.signature")
        id_token = self.mock_validator.finalize_id_token.call_args[0][0]
        self.assertEqual(id_token['nonce'], 'my_nonce')

    async def test_finalize_id_token_with_at_hash(self):
        self.token["access_token"] = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request)
        self.assertIn("id_token", token)
        self.assertEqual(token["id_token"], "eyJ.body.signature")
        id_token = self.mock_validator.finalize_id_token.call_args[0][0]
        self.assertEqual(id_token['at_hash'], 'LDktKdoQak3Pk0cnXxCltA')

    async def test_finalize_id_token_with_c_hash(self):
        self.token["code"] = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request)
        self.assertIn("id_token", token)
        self.assertEqual(token["id_token"], "eyJ.body.signature")
        id_token = self.mock_validator.finalize_id_token.call_args[0][0]
        self.assertEqual(id_token['c_hash'], 'LDktKdoQak3Pk0cnXxCltA')

    async def test_finalize_id_token_with_c_and_at_hash(self):
        self.token["code"] = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
        self.token["access_token"] = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
        token = await self.grant.add_id_token(self.token, "token_handler_mock", self.request)
        self.assertIn("id_token", token)
        self.assertEqual(token["id_token"], "eyJ.body.signature")
        id_token = self.mock_validator.finalize_id_token.call_args[0][0]
        self.assertEqual(id_token['at_hash'], 'LDktKdoQak3Pk0cnXxCltA')
        self.assertEqual(id_token['c_hash'], 'LDktKdoQak3Pk0cnXxCltA')
