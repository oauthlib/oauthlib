# -*- coding: utf-8 -*-
import json
from unittest import mock

from oauthlib.oauth2.rfc8628.endpoints import DeviceAuthorizationEndpoint

from tests.unittest import TestCase


class DeviceAuthorizationEndpointTest(TestCase):
    def setUp(self):
        self.verification_uri = "http://i.b/l/verify"
        self.uri = "http://i.b/l"

    @mock.patch("oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token")
    def test_device_authorization_grant(self, generate_token):
        generate_token.side_effect = ["abc", "def"]
        endpoint = DeviceAuthorizationEndpoint(verification_uri=self.verification_uri)
        _, body, status_code = endpoint.create_device_authorization_response(self.uri)
        expected_payload = {
            "verification_uri": "http://i.b/l/verify",
            "user_code": "abc",
            "device_code": "def",
            "expires_in": 1800,
        }
        self.assertEqual(200, status_code)
        self.assertEqual(json.loads(body), expected_payload)

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_interval(self):
        endpoint = DeviceAuthorizationEndpoint(
            verification_uri=self.verification_uri, interval=5
        )
        _, body, _ = endpoint.create_device_authorization_response(self.uri)
        self.assertEqual(5, json.loads(body)["interval"])

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_interval_with_zero(self):
        endpoint = DeviceAuthorizationEndpoint(
            verification_uri=self.verification_uri, interval=0
        )
        _, body, _ = endpoint.create_device_authorization_response(self.uri)
        self.assertEqual(0, json.loads(body)["interval"])

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_verify_url_complete_string(self):
        endpoint = DeviceAuthorizationEndpoint(
            verification_uri=self.verification_uri,
            verification_uri_complete="http://i.l/v?user_code={user_code}",
        )
        _, body, _ = endpoint.create_device_authorization_response(self.uri)
        self.assertEqual(
            "http://i.l/v?user_code=abc",
            json.loads(body)["verification_uri_complete"],
        )

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_verify_url_complete_callable(self):
        endpoint = DeviceAuthorizationEndpoint(
            verification_uri=self.verification_uri,
            verification_uri_complete=lambda u: f"http://i.l/v?user_code={u}",
        )
        _, body, _ = endpoint.create_device_authorization_response(self.uri)
        self.assertEqual(
            "http://i.l/v?user_code=abc",
            json.loads(body)["verification_uri_complete"],
        )
