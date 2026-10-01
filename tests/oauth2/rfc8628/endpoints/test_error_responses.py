import json
from unittest import TestCase, mock

from oauthlib.common import Request, urlencode
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc8628.endpoints.pre_configured import DeviceApplicationServer
from oauthlib.oauth2.rfc8628.request_validator import RequestValidator


class ErrorResponseTest(TestCase):
    def set_client(self, request, *args, **kwargs):
        """Stand in for a validator that attaches the client, as documented."""
        request.client = mock.MagicMock()
        request.client.client_id = request.client_id
        return True

    def set_client_id(self, client_id, request, *args, **kwargs):
        return self.set_client(request)

    def build_request(
        self, uri="https://example.com/device_authorize", client_id="foo", body=None
    ):
        # The body must be passed to the constructor: Request parses it once at
        # initialization, so assigning to request.body afterwards would leave
        # request.scope and request.duplicate_params stale.
        if body is None:
            body = f"client_id={client_id}" if client_id else ""
        return Request(
            uri,
            http_method="POST",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def assert_request_raises(self, error, request, description=None):
        """Test that the request fails similarly on the validation and response endpoint."""
        with self.assertRaises(error) as caught:
            self.device.validate_device_authorization_request(request)
        if description is not None:
            self.assertEqual(description, caught.exception.description)

        with self.assertRaises(error) as caught:
            self.device.create_device_authorization_response(
                uri=request.uri,
                http_method=request.http_method,
                body=request.body,
                headers=request.headers,
            )
        if description is not None:
            self.assertEqual(description, caught.exception.description)

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = None
        self.validator.get_code_challenge.return_value = None
        self.validator.authenticate_client.side_effect = self.set_client
        self.validator.authenticate_client_id.side_effect = self.set_client_id
        self.device = DeviceApplicationServer(self.validator, "https://example.com/verify")

    def test_missing_client_id(self):
        # Device code grant
        request = self.build_request(client_id=None)
        self.assert_request_raises(errors.MissingClientIdError, request)

    def test_empty_client_id(self):
        # Device code grant
        self.assertRaises(
            errors.MissingClientIdError,
            self.device.create_device_authorization_response,
            "https://i.l/",
            "POST",
            "client_id=",
            {"Content-Type": "application/x-www-form-urlencoded"},
        )

    def test_invalid_client_id(self):
        request = self.build_request(client_id="foo")
        # Device code grant
        self.validator.validate_client_id.return_value = False
        self.assert_request_raises(errors.InvalidClientIdError, request)

    def test_duplicate_client_id(self):
        request = self.build_request(body="client_id=foo&client_id=bar")
        # Device code grant
        self.assert_request_raises(
            errors.InvalidRequestFatalError, request, "Duplicate client_id parameter."
        )

    def test_unauthenticated_confidential_client(self):
        self.validator.client_authentication_required.return_value = True
        self.validator.authenticate_client.side_effect = None
        self.validator.authenticate_client.return_value = False
        request = self.build_request()
        self.assert_request_raises(errors.InvalidClientError, request)

    def test_unauthenticated_public_client(self):
        self.validator.client_authentication_required.return_value = False
        self.validator.authenticate_client_id.side_effect = None
        self.validator.authenticate_client_id.return_value = False
        request = self.build_request()
        self.assert_request_raises(errors.InvalidClientError, request)

    def test_duplicate_scope_parameter(self):
        request = self.build_request(body="client_id=foo&scope=foo&scope=bar")
        # Device code grant
        self.assert_request_raises(
            errors.InvalidRequestFatalError, request, "Duplicate scope parameter."
        )

    def test_invalid_scope(self):
        request = self.build_request(body="client_id=foo&scope=foo")

        # Only reject the scope requested in the body, so that the test fails if
        # the requested scope never reaches the validator.
        def validate_scopes(client_id, scopes, client, request):
            return scopes != ["foo"]

        self.validator.validate_scopes.side_effect = validate_scopes
        self.assert_request_raises(errors.InvalidScopeError, request)
