import json
from unittest import mock

from oauthlib.oauth2.rfc8628.endpoints import DeviceAuthorizationEndpoint
from oauthlib.oauth2.rfc8628.request_validator import RequestValidator

from tests.unittest import TestCase


class DeviceAuthorizationEndpointTest(TestCase):
    def _set_client(self, request, *args, **kwargs):
        """Stand in for a validator that attaches the client, as documented."""
        request.client = mock.MagicMock()
        request.client.client_id = request.client_id
        return True

    def _build_validator(self, scopes=None):
        validator = mock.MagicMock(spec=RequestValidator)
        validator.authenticate_client.side_effect = self._set_client
        validator.authenticate_client_id.side_effect = (
            lambda client_id, request, *a, **kw: self._set_client(request)
        )
        validator.get_default_scopes.return_value = scopes
        return validator

    def _configure_endpoint(
        self,
        interval=None,
        verification_uri_complete=None,
        user_code_generator=None,
        scopes=None,
    ):
        self.endpoint = DeviceAuthorizationEndpoint(
            request_validator=self._build_validator(scopes),
            verification_uri=self.verification_uri,
            interval=interval,
            verification_uri_complete=verification_uri_complete,
            user_code_generator=user_code_generator,
        )

    def setUp(self):
        self.verification_uri = "http://i.b/l/verify"
        self.uri = "http://i.b/l"
        self.http_method = "POST"
        self.body = "client_id=abc"
        self.headers = {"Content-Type": "application/x-www-form-urlencoded"}
        self._configure_endpoint()

    def response_payload(self):
        return self.uri, self.http_method, self.body, self.headers

    @mock.patch("oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token")
    def test_device_authorization_grant(self, generate_token):
        generate_token.side_effect = ["abc", "def"]
        _, body, status_code = self.endpoint.create_device_authorization_response(
            *self.response_payload()
        )
        expected_payload = {
            "verification_uri": "http://i.b/l/verify",
            "user_code": "abc",
            "device_code": "def",
            "expires_in": 1800,
        }
        self.assertEqual(200, status_code)
        self.assertEqual(body, expected_payload)

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_echoes_requested_scope(self):
        self.body = "client_id=abc&scope=read+write"
        _, body, _ = self.endpoint.create_device_authorization_response(*self.response_payload())
        self.assertEqual("read write", body["scope"])

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_echoes_default_scope(self):
        """A device that omits scope gets the resolved defaults back (issue #949)."""
        self._configure_endpoint(scopes=["read", "write"])
        _, body, _ = self.endpoint.create_device_authorization_response(*self.response_payload())
        self.assertEqual("read write", body["scope"])

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_interval(self):
        self._configure_endpoint(interval=5)
        _, body, _ = self.endpoint.create_device_authorization_response(*self.response_payload())
        self.assertEqual(5, body["interval"])

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_interval_with_zero(self):
        self._configure_endpoint(interval=0)
        _, body, _ = self.endpoint.create_device_authorization_response(*self.response_payload())
        self.assertEqual(0, body["interval"])

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_verify_url_complete_string(self):
        self._configure_endpoint(verification_uri_complete="http://i.l/v?user_code={user_code}")
        _, body, _ = self.endpoint.create_device_authorization_response(*self.response_payload())
        self.assertEqual(
            "http://i.l/v?user_code=abc",
            body["verification_uri_complete"],
        )

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_verify_url_complete_callable(self):
        self._configure_endpoint(verification_uri_complete=lambda u: f"http://i.l/v?user_code={u}")
        _, body, _ = self.endpoint.create_device_authorization_response(*self.response_payload())
        self.assertEqual(
            "http://i.l/v?user_code=abc",
            body["verification_uri_complete"],
        )

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_authorization_grant_user_gode_generator(self):
        def user_code():
            """
            A friendly user code the device can display and the user
            can type in. It's up to the device how
            this code should be displayed. e.g 123-456
            """
            return "123456"

        self._configure_endpoint(
            verification_uri_complete=lambda u: f"http://i.l/v?user_code={u}",
            user_code_generator=user_code,
        )

        _, body, _ = self.endpoint.create_device_authorization_response(*self.response_payload())
        self.assertEqual(
            "http://i.l/v?user_code=123456",
            body["verification_uri_complete"],
        )
