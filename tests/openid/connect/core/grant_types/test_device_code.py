import json
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.openid.connect.core.grant_types import DeviceCodeGrant

from tests.unittest import TestCase


def get_id_token_mock(token, token_handler, request):
    return "MOCKED_TOKEN"


class OpenIDDeviceCodeGrantTest(TestCase):

    def setUp(self):
        self.request = Request("http://a.b/path")
        self.request.grant_type = "urn:ietf:params:oauth:grant-type:device_code"
        self.request.scopes = ("hello", "openid")
        self.request.client = mock.MagicMock()
        self.request.client.client_id = "mocked"
        # leftover from an earlier authorize step must not block id_token
        self.request.response_type = "code"

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = self.set_client
        self.mock_validator.get_id_token.side_effect = get_id_token_mock
        self.mock_validator.get_default_scopes.return_value = ["hello", "openid"]
        self.auth = DeviceCodeGrant(request_validator=self.mock_validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = "mocked"
        return True

    def test_device_code_includes_id_token_for_openid(self):
        bearer = BearerToken(self.mock_validator)
        _headers, body, _status = self.auth.create_token_response(
            self.request, bearer
        )
        token = json.loads(body)
        self.assertIn("access_token", token)
        self.assertIn("id_token", token)
        self.assertEqual(token["id_token"], "MOCKED_TOKEN")

    def test_device_code_skips_id_token_without_openid(self):
        self.request.scopes = ("hello",)
        bearer = BearerToken(self.mock_validator)
        _headers, body, _status = self.auth.create_token_response(
            self.request, bearer
        )
        token = json.loads(body)
        self.assertIn("access_token", token)
        self.assertNotIn("id_token", token)

    def test_add_id_token_does_not_leave_response_type_on_request(self):
        request = Request("http://a.b/path")
        request.grant_type = "urn:ietf:params:oauth:grant-type:device_code"
        request.scopes = ("openid",)
        self.assertNotIn("response_type", vars(request))
        bearer = BearerToken(self.mock_validator)
        self.auth.add_id_token({"access_token": "a"}, bearer, request)
        self.assertNotIn("response_type", vars(request))
