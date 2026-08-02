"""Reproducer for oauthlib#949: Device Authorization Grant skips scope validation.

``DeviceAuthorizationEndpoint.validate_device_authorization_request`` never
calls ``get_default_scopes`` / ``validate_scopes`` on the request validator,
unlike every other oauthlib authorization endpoint.  The two consequences:

1. When the request omits ``scope``, the default scopes are never resolved
   and are missing from the response returned by
   ``create_device_authorization_response``.
2. When the request provides ``scope``, the requested scopes are never
   validated against the client.
"""

import pytest

from oauthlib.common import urlencode
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc8628.endpoints.pre_configured import DeviceApplicationServer
from oauthlib.oauth2.rfc8628.request_validator import RequestValidator


DEVICE_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


def _device_body(**extra):
    """Build a urlencoded device authorization request body."""
    return urlencode([("client_id", "myclient"), *extra.items()])


class _TrackingValidator(RequestValidator):
    """Minimal device-flow validator that records scope calls."""

    def __init__(self, validate_scopes=True, default_scopes=("read", "write")):
        self.validate_scopes_ok = validate_scopes
        self.default_scopes = default_scopes
        self.get_default_scopes_calls = []
        self.validate_scopes_calls = []

    def validate_client_id(self, client_id, request, *args, **kwargs):
        return True

    def authenticate_client(self, request, *args, **kwargs):
        request.client = type("Client", (), {"client_id": request.client_id})()
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        self.get_default_scopes_calls.append((client_id, request))
        return list(self.default_scopes)

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        self.validate_scopes_calls.append((client_id, scopes))
        return self.validate_scopes_ok


def _server(validator):
    return DeviceApplicationServer(validator, verification_uri="https://example.com/device")


def test_default_scopes_are_never_resolved_when_scope_omitted():
    """BUG: get_default_scopes() is not called and scope is missing from the response."""
    validator = _TrackingValidator()
    server = _server(validator)

    _, data, _ = server.create_device_authorization_response(
        "https://example.com/device_authorization",
        http_method="POST",
        body=_device_body(),
        headers=DEVICE_HEADERS,
    )

    assert validator.get_default_scopes_calls, (
        "expected get_default_scopes() to be called when scope is omitted"
    )
    assert data.get("scope") == "read write", (
        "expected the resolved default scopes to be included in the response, "
        "got %r" % data.get("scope")
    )


def test_requested_scopes_are_never_validated():
    """BUG: validate_scopes() is not called for a provided scope."""
    validator = _TrackingValidator(validate_scopes=False)
    server = _server(validator)

    with pytest.raises(errors.InvalidScopeError):
        server.create_device_authorization_response(
            "https://example.com/device_authorization",
            http_method="POST",
            body=_device_body(scope="read"),
            headers=DEVICE_HEADERS,
        )

    assert validator.validate_scopes_calls, (
        "expected validate_scopes() to be called with the requested scope"
    )


def test_requested_scope_is_validated_and_echoed():
    """A provided scope is validated and echoed in the response."""
    validator = _TrackingValidator()
    server = _server(validator)

    _, data, status = server.create_device_authorization_response(
        "https://example.com/device_authorization",
        http_method="POST",
        body=_device_body(scope="read email"),
        headers=DEVICE_HEADERS,
    )

    assert status == 200
    assert validator.validate_scopes_calls == [("myclient", ["read", "email"])]
    assert validator.get_default_scopes_calls == []
    assert data.get("scope") == "read email"
