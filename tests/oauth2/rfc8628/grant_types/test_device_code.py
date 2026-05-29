import json
from unittest import mock
import pytest

from oauthlib import common

from oauthlib.oauth2.rfc8628.grant_types import DeviceCodeGrant
from oauthlib.oauth2.rfc8628.request_validator import RequestValidator
from oauthlib.oauth2.rfc6749.tokens import BearerToken

def create_request(body: str = "") -> common.Request:
    request = common.Request("http://a.b/path", body=body or None)
    request.scopes = ("hello", "world")
    request.expires_in = 1800
    request.client = "batman"
    request.client_id = "abcdef"
    request.code = "1234"
    request.response_type = "code"
    request.grant_type = "urn:ietf:params:oauth:grant-type:device_code"
    request.redirect_uri = "https://a.b/"
    request.device_code = "device_code_1234"
    return request


def create_device_code_grant(mock_validator: mock.MagicMock) -> DeviceCodeGrant:
    return DeviceCodeGrant(request_validator=mock_validator)


def test_custom_auth_validators_unsupported():
    custom_validator = mock.Mock()
    validator = mock.MagicMock()

    expected = (
        "DeviceCodeGrant does not "
        "support authorization validators. Use token validators instead."
    )
    with pytest.raises(ValueError, match=expected):
        DeviceCodeGrant(validator, pre_auth=[custom_validator])

    with pytest.raises(ValueError, match=expected):
        DeviceCodeGrant(validator, post_auth=[custom_validator])

    expected = "'tuple' object has no attribute 'append'"
    auth = DeviceCodeGrant(validator)
    with pytest.raises(AttributeError, match=expected):
        auth.custom_validators.pre_auth.append(custom_validator)


def test_custom_pre_and_post_token_validators():
    client = mock.MagicMock()

    validator = mock.MagicMock()
    pre_token_validator = mock.Mock()
    post_token_validator = mock.Mock()

    request: common.Request = create_request()
    request.client = client
    validator.validate_device_code.return_value = DeviceCodeGrant.DEVICE_CODE_AUTHORIZED

    auth = DeviceCodeGrant(validator)

    auth.custom_validators.pre_token.append(pre_token_validator)
    auth.custom_validators.post_token.append(post_token_validator)

    bearer = BearerToken(validator)
    auth.create_token_response(request, bearer)

    pre_token_validator.assert_called()
    post_token_validator.assert_called()


def test_create_token_response():
    validator = mock.MagicMock()
    request: common.Request = create_request()
    request.client = mock.Mock()
    validator.validate_device_code.return_value = DeviceCodeGrant.DEVICE_CODE_AUTHORIZED

    auth = DeviceCodeGrant(validator)

    bearer = BearerToken(validator)

    headers, body, status_code = auth.create_token_response(request, bearer)
    token = json.loads(body)

    assert headers == {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }

    # when a custom token generator callable isn't used
    # the random generator is used as default for the access token
    assert token == {
        "access_token": mock.ANY,
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": "hello world",
        "refresh_token": mock.ANY,
    }

    assert status_code == 200

    validator.save_token.assert_called_once()


def test_invalid_client_authentication_error_confidential_client():
    validator = mock.MagicMock()
    request: common.Request = create_request()
    request.client = mock.Mock()

    auth = DeviceCodeGrant(validator)
    bearer = BearerToken(validator)

    # Simulate a confidential client that requires authentication
    validator.client_authentication_required.return_value = True
    validator.authenticate_client.return_value = False

    headers, body, status_code = auth.create_token_response(request, bearer)
    body = json.loads(body)

    assert headers == {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "WWW-Authenticate": 'Bearer error="invalid_client"',
    }
    assert body == {"error": "invalid_client"}
    assert status_code == 401

    validator.save_token.assert_not_called()


def test_invalid_client_authentication_error_public_client():
    validator = mock.MagicMock()
    request: common.Request = create_request()
    request.client = mock.Mock()

    auth = DeviceCodeGrant(validator)
    bearer = BearerToken(validator)

    # Simulate a public client that does not require authentication
    validator.client_authentication_required.return_value = False
    validator.authenticate_client_id.return_value = False

    headers, body, status_code = auth.create_token_response(request, bearer)
    body = json.loads(body)

    assert headers == {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "WWW-Authenticate": 'Bearer error="invalid_client"',
    }
    assert body == {"error": "invalid_client"}
    assert status_code == 401

    validator.save_token.assert_not_called()


def test_invalid_grant_type_error():
    validator = mock.MagicMock()
    request: common.Request = create_request()
    request.client = mock.Mock()

    request.grant_type = "not_device_code"

    auth = DeviceCodeGrant(validator)
    bearer = BearerToken(validator)

    headers, body, status_code = auth.create_token_response(request, bearer)
    body = json.loads(body)

    assert headers == {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
    assert body == {"error": "unsupported_grant_type"}
    assert status_code == 400

    validator.save_token.assert_not_called()


def test_duplicate_params_error():
    validator = mock.MagicMock()
    request: common.Request = create_request(
        "client_id=123&scope=openid&scope=openid"
    )
    request.client = mock.Mock()

    auth = DeviceCodeGrant(validator)
    bearer = BearerToken(validator)

    headers, body, status_code = auth.create_token_response(request, bearer)
    body = json.loads(body)

    assert headers == {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
    assert body == {"error": "invalid_request", "error_description": "Duplicate scope parameter."}
    assert status_code == 400

    validator.save_token.assert_not_called()


@pytest.mark.parametrize(
    "status, expected_error",
    [
        (DeviceCodeGrant.DEVICE_CODE_PENDING, "authorization_pending"),
        (DeviceCodeGrant.DEVICE_CODE_SLOW_DOWN, "slow_down"),
        (DeviceCodeGrant.DEVICE_CODE_EXPIRED, "expired_token"),
        (DeviceCodeGrant.DEVICE_CODE_DENIED, "access_denied"),
    ],
)
def test_device_code_status_errors(status, expected_error):
    validator = mock.MagicMock()
    request: common.Request = create_request()
    request.client = mock.Mock()
    validator.validate_device_code.return_value = status

    auth = DeviceCodeGrant(validator)
    bearer = BearerToken(validator)

    headers, body, status_code = auth.create_token_response(request, bearer)
    body = json.loads(body)

    assert body == {"error": expected_error}
    assert status_code == 400

    validator.validate_device_code.assert_called_once_with(
        request.client_id, request.device_code, request
    )
    validator.save_token.assert_not_called()


@pytest.mark.parametrize(
    "status",
    [
        None,  # documented "unknown / invalid device_code" return
        "not_a_real_status",  # validator returned an unrecognized value
        True,  # validator wrongly returned a bool instead of a status
    ],
)
def test_invalid_device_code(status):
    validator = mock.MagicMock()
    request: common.Request = create_request()
    request.client = mock.Mock()
    validator.validate_device_code.return_value = status

    auth = DeviceCodeGrant(validator)
    bearer = BearerToken(validator)

    headers, body, status_code = auth.create_token_response(request, bearer)
    body = json.loads(body)

    assert body == {"error": "invalid_grant"}
    assert status_code == 400

    validator.save_token.assert_not_called()


def test_device_code_scopes_populated_before_scope_validation():
    """Authorized scopes from the stored grant must be validated, not defaults.

    Per RFC 8628 Section 3.4 the device token request carries no scope, so
    validate_device_code must populate request.scopes from the stored
    authorization before validate_scopes runs; otherwise validate_scopes falls
    back to get_default_scopes and the token silently receives default scopes
    (issue #944).
    """
    validator = mock.MagicMock()
    request: common.Request = create_request()
    request.client = mock.Mock()
    # The device token request has no scope of its own.
    request.scope = None
    request.scopes = None

    def authorize(client_id, code, req):
        req.scopes = ["read", "write"]
        return DeviceCodeGrant.DEVICE_CODE_AUTHORIZED

    validator.validate_device_code.side_effect = authorize

    auth = DeviceCodeGrant(validator)
    bearer = BearerToken(validator)
    auth.create_token_response(request, bearer)

    validator.get_default_scopes.assert_not_called()
    validator.validate_scopes.assert_called_once_with(
        "abcdef", ["read", "write"], request.client, request
    )


def test_validate_device_code_is_required_on_real_validator():
    """The hook lives on the rfc8628 RequestValidator and must be implemented.

    Guards against the gap mocks hide: a MagicMock auto-creates
    ``validate_device_code``, so the behavior tests above pass even if the
    method did not exist. A real validator subclass that has not implemented
    it must fail loudly rather than silently.
    """
    request: common.Request = create_request()
    with pytest.raises(NotImplementedError):
        RequestValidator().validate_device_code(
            request.client_id, request.device_code, request
        )


def test_missing_device_code():
    validator = mock.MagicMock()
    request: common.Request = create_request()
    request.client = mock.Mock()
    request.device_code = None

    auth = DeviceCodeGrant(validator)
    bearer = BearerToken(validator)

    headers, body, status_code = auth.create_token_response(request, bearer)
    body = json.loads(body)

    assert body == {
        "error": "invalid_request",
        "error_description": "Missing device_code parameter.",
    }
    assert status_code == 400

    validator.validate_device_code.assert_not_called()
    validator.save_token.assert_not_called()
