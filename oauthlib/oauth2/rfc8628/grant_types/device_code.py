from __future__ import annotations
import json
import logging

from typing import Callable

from oauthlib import common # noqa: TC001

from oauthlib.oauth2.rfc6749 import errors as rfc6749_errors
from oauthlib.oauth2.rfc6749.grant_types.base import GrantTypeBase
from oauthlib.oauth2.rfc8628 import errors as rfc8628_errors

log = logging.getLogger(__name__)


class DeviceCodeGrant(GrantTypeBase):
    #: Maps a non-authorized device code status to the RFC 8628 Section 3.5
    #: error it raises. The status strings are the errors' own ``error`` codes,
    #: keeping a single source of truth.
    _device_code_errors = {
        cls.error: cls
        for cls in (
            rfc8628_errors.AuthorizationPendingError,
            rfc8628_errors.SlowDownError,
            rfc8628_errors.ExpiredTokenError,
            rfc8628_errors.AccessDenied,
        )
    }

    #: Authorization statuses returned by
    #: :meth:`RequestValidator.validate_device_code`, per RFC 8628 Section 3.5.
    DEVICE_CODE_AUTHORIZED = "authorized"
    DEVICE_CODE_PENDING = rfc8628_errors.AuthorizationPendingError.error
    DEVICE_CODE_SLOW_DOWN = rfc8628_errors.SlowDownError.error
    DEVICE_CODE_EXPIRED = rfc8628_errors.ExpiredTokenError.error
    DEVICE_CODE_DENIED = rfc8628_errors.AccessDenied.error

    def create_authorization_response(
        self, request: common.Request, token_handler: Callable
    ) -> tuple[dict, str, int]:
        """
        Validate the device flow request -> create the access token
        -> persist the token -> return the token.
        """
        headers = self._get_default_headers()
        try:
            self.validate_token_request(request)
        except rfc6749_errors.OAuth2Error as e:
            headers.update(e.headers)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, refresh_token=False)

        for modifier in self._token_modifiers:
            token = modifier(token)

        self.request_validator.save_token(token, request)

        return self.create_token_response(request, token_handler)

    def validate_device_authorization_request(self, request: common.Request) -> None:
        """Validate the device authorization request.

        The client_id is required if the client is not authenticating with the
        authorization server as described in `Section 3.2.1. of [RFC6749]`_.
        The client identifier as described in `Section 2.2 of [RFC6749]`_.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request

        .. _`Section 3.2.1. of [RFC6749]`: https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1
        .. _`Section 2.2 of [RFC6749]`: https://www.rfc-editor.org/rfc/rfc6749#section-2.2
        """
        # First check duplicate parameters
        for param in ("client_id", "scope"):
            try:
                duplicate_params = request.duplicate_params
            except ValueError:
                raise rfc6749_errors.InvalidRequestFatalError(
                    description="Unable to parse query string", request=request
                )
            if param in duplicate_params:
                raise rfc6749_errors.InvalidRequestFatalError(
                    description="Duplicate %s parameter." % param, request=request
                )

        # the "application/x-www-form-urlencoded" format, per Appendix B of [RFC6749]
        # https://www.rfc-editor.org/rfc/rfc6749#appendix-B
        if request.headers["Content-Type"] != "application/x-www-form-urlencoded":
            raise rfc6749_errors.InvalidRequestError(
                "Content-Type must be application/x-www-form-urlencoded",
                request=request,
            )

        # REQUIRED. The client identifier as described in Section 2.2.
        # https://tools.ietf.org/html/rfc6749#section-2.2
        if not request.client_id:
            raise rfc6749_errors.MissingClientIdError(request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise rfc6749_errors.InvalidClientIdError(request=request)

        # The client authentication requirements of Section 3.2.1 of [RFC6749]
        # apply to requests on this endpoint, which means that confidential
        # clients (those that have established client credentials) authenticate
        # in the same manner as when making requests to the token endpoint, and
        # public clients provide the "client_id" parameter to identify
        # themselves.
        self.validate_client_authentication(request)

        # OPTIONAL. The scope of the access request as defined by Section 3.3
        # of [RFC6749]. https://www.rfc-editor.org/rfc/rfc8628#section-3.1
        self.validate_scopes(request)

    def validate_token_request(self, request: common.Request) -> None:
        """
        Performs the necessary check against the request to ensure
        it's allowed to retrieve a token.
        """
        for validator in self.custom_validators.pre_token:
            validator(request)

        if not getattr(request, "grant_type", None):
            raise rfc6749_errors.InvalidRequestError(
                "Request is missing grant type.", request=request
            )

        if request.grant_type != "urn:ietf:params:oauth:grant-type:device_code":
            raise rfc6749_errors.UnsupportedGrantTypeError(request=request)

        for param in ("grant_type", "scope"):
            if param in request.duplicate_params:
                raise rfc6749_errors.InvalidRequestError(
                    description=f"Duplicate {param} parameter.", request=request
                )

        self.validate_client_authentication(request)

        if not hasattr(request.client, 'client_id'):
            raise NotImplementedError('Authenticate client must set the '
                                      'request.client.client_id attribute '
                                      'in authenticate_client.')

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        request.client_id = request.client_id or request.client.client_id

        # Validate the device_code first: per RFC 8628 Section 3.4 the token
        # request carries no scope, so the validator must populate
        # request.user and request.scopes from the stored authorization before
        # validate_scopes runs (otherwise it would fall back to default scopes).
        self.validate_device_code(request)

        self.validate_scopes(request)

        for validator in self.custom_validators.post_token:
            validator(request)

    def validate_device_code(self, request: common.Request) -> None:
        """Validate the ``device_code`` and its authorization status.

        Delegates to :meth:`RequestValidator.validate_device_code`, which
        returns one of the ``DEVICE_CODE_*`` statuses, and maps it to the
        appropriate RFC 8628 Section 3.5 error.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        if not request.device_code:
            raise rfc6749_errors.InvalidRequestError(
                "Missing device_code parameter.", request=request
            )

        status = self.request_validator.validate_device_code(
            request.client_id, request.device_code, request
        )
        if status == self.DEVICE_CODE_AUTHORIZED:
            return

        # A recognized non-authorized status maps to its RFC 8628 polling
        # error; anything else means the device_code is unknown or invalid.
        error_class = self._device_code_errors.get(status)
        if error_class is not None:
            raise error_class(request=request)

        # None is the documented "unknown/invalid device_code" return. Any
        # other unrecognized value most likely signals a validator that did
        # not return a DEVICE_CODE_* status, so surface it for debugging.
        if status is not None:
            log.warning(
                "validate_device_code returned unrecognized status %r; treating "
                "the device_code as invalid. Return one of the "
                "DeviceCodeGrant.DEVICE_CODE_* constants.", status
            )
        raise rfc6749_errors.InvalidGrantError(request=request)

    def create_token_response(
        self, request: common.Request, token_handler: Callable
    ) -> tuple[dict, str, int]:
        """Return token or error in json format.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request failed client
        authentication or is invalid, the authorization server returns an
        error response as described in `Section 5.2`_.
        .. _`Section 5.1`: https://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: https://tools.ietf.org/html/rfc6749#section-5.2
        """
        headers = self._get_default_headers()
        try:
            self.validate_token_request(request)
        except rfc6749_errors.OAuth2Error as e:
            headers.update(e.headers)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, self.refresh_token)

        self.request_validator.save_token(token, request)

        return headers, json.dumps(token), 200
