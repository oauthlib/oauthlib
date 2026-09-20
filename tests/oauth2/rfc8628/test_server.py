import json
from unittest import mock

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc8628.endpoints import DeviceAuthorizationEndpoint
from oauthlib.oauth2.rfc8628.request_validator import RequestValidator

from tests.unittest import TestCase


class DeviceAuthorizationEndpointTest(TestCase):
    def _configure_endpoint(
        self, interval=None, verification_uri_complete=None, user_code_generator=None
    ):
        validator = mock.MagicMock(spec=RequestValidator)
        validator.get_default_scopes.return_value = []
        self.endpoint = DeviceAuthorizationEndpoint(
            request_validator=validator,
            verification_uri=self.verification_uri,
            interval=interval,
            verification_uri_complete=verification_uri_complete,
            user_code_generator=user_code_generator,
        )

    def setUp(self):
        self.request_validator = mock.MagicMock(spec=RequestValidator)
        self.request_validator.get_default_scopes.return_value = []
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


class DeviceAuthorizationScopesTest(TestCase):
    """Regression tests for https://github.com/oauthlib/oauthlib/issues/949.

    The device authorization endpoint must resolve default scopes when the
    device requests none and validate any requested scopes, mirroring the
    authorization code flow.
    """

    class StubValidator(RequestValidator):
        def __init__(self):
            self.default_scopes = ["read", "write"]
            self.validated = None

        def validate_client_id(self, client_id, request, *args, **kwargs):
            return True

        def client_authentication_required(self, request, *args, **kwargs):
            return False

        def authenticate_client_id(self, client_id, request, *args, **kwargs):
            return True

        def get_default_scopes(self, client_id, request, *args, **kwargs):
            return self.default_scopes

        def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
            self.validated = (client_id, list(scopes))
            return set(scopes) <= {"read", "write"}

    def setUp(self):
        self.validator = self.StubValidator()
        self.endpoint = DeviceAuthorizationEndpoint(
            request_validator=self.validator,
            verification_uri="http://i.b/l/verify",
        )
        self.uri = "http://i.b/l"
        self.headers = {"Content-Type": "application/x-www-form-urlencoded"}

    def test_default_scopes_resolved_when_scope_missing(self):
        _, body, status_code = self.endpoint.create_device_authorization_response(
            self.uri, "POST", "client_id=abc", self.headers
        )
        self.assertEqual(200, status_code)
        self.assertEqual("read write", body["scope"])
        self.assertEqual(("abc", ["read", "write"]), self.validator.validated)

    def test_requested_scopes_are_validated(self):
        _, body, status_code = self.endpoint.create_device_authorization_response(
            self.uri, "POST", "client_id=abc&scope=read", self.headers
        )
        self.assertEqual(200, status_code)
        self.assertEqual("read", body["scope"])
        self.assertEqual(("abc", ["read"]), self.validator.validated)

    def test_invalid_scope_is_rejected(self):
        with self.assertRaises(errors.InvalidScopeError):
            self.endpoint.create_device_authorization_response(
                self.uri, "POST", "client_id=abc&scope=admin", self.headers
            )
