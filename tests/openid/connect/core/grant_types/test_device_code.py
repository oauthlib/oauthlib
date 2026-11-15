import json
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc8628.grant_types import (
    DeviceCodeGrant as OAuth2DeviceCodeGrant,
)
from oauthlib.openid.connect.core.endpoints.pre_configured import Server
from oauthlib.openid.connect.core.grant_types import DeviceCodeGrant

from tests.unittest import TestCase


def get_id_token_mock(token, token_handler, request):
    return "MOCKED_TOKEN"


class OpenIDDeviceCodeTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
        self.request.device_code = 'device_code_1234'
        self.request.client_id = 'mocked'

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = self.set_client
        self.mock_validator.get_id_token.side_effect = get_id_token_mock
        self.scopes = ['hello', 'openid']
        self.mock_validator.validate_device_code.side_effect = self.authorize
        self.auth = DeviceCodeGrant(request_validator=self.mock_validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def authorize(self, client_id, device_code, request):
        request.scopes = self.scopes
        return OAuth2DeviceCodeGrant.DEVICE_CODE_AUTHORIZED

    def test_id_token_with_openid_scope(self):
        bearer = BearerToken(self.mock_validator)
        _headers, body, status_code = self.auth.create_token_response(
            self.request, bearer
        )
        token = json.loads(body)
        self.assertEqual(status_code, 200)
        self.assertEqual(token['id_token'], 'MOCKED_TOKEN')
        self.assertIn('access_token', token)
        self.assertEqual(self.mock_validator.save_token.call_count, 1)
        saved = self.mock_validator.save_token.call_args[0][0]
        self.assertEqual(saved['id_token'], 'MOCKED_TOKEN')

    def test_no_id_token_without_openid_scope(self):
        self.scopes = ['hello']
        bearer = BearerToken(self.mock_validator)
        _headers, body, status_code = self.auth.create_token_response(
            self.request, bearer
        )
        token = json.loads(body)
        self.assertEqual(status_code, 200)
        self.assertNotIn('id_token', token)
        self.mock_validator.get_id_token.assert_not_called()

    def test_pre_configured_server_returns_id_token(self):
        server = Server(self.mock_validator)
        _headers, body, status_code = server.create_token_response(
            'https://a.b/token',
            http_method='POST',
            body='grant_type=urn:ietf:params:oauth:grant-type:device_code'
                 '&device_code=device_code_1234&client_id=mocked',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        token = json.loads(body)
        self.assertEqual(status_code, 200, body)
        self.assertEqual(token['id_token'], 'MOCKED_TOKEN')
