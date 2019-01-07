# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.draft_ietf13.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import absolute_import, unicode_literals

import json
import logging

from oauthlib import common
from oauthlib.uri_validate import is_absolute_uri

from oauthlib.oauth2.rfc6749.grant_types.base import GrantTypeBase
from oauthlib.oauth2.rfc6749 import errors

# TODO: How do we import this base class ?
#
# from oauthlib.oauth2.grant_types.base import GrantTypeBase

log = logging.getLogger(__name__)


class DeviceCodeGrant(GrantTypeBase):

    """`Device Code Grant`_

    This OAuth 2.0 [RFC6749] protocol flow for browserless and input-
    constrained devices, often referred to as the device flow, enables
    OAuth clients to request user authorization from applications on
    devices that have an Internet connection, but don't have an easy
    input method (such as a smart TV, media console, picture frame, or
    printer), or lack a suitable browser for a more traditional OAuth
    flow.  This authorization flow instructs the user to perform the
    authorization request on a secondary device, such as a smartphone.

    The device flow is not intended to replace browser-based OAuth in
    native apps on capable devices (like smartphones).  Those apps should
    follow the practices specified in OAuth 2.0 for Native Apps
    [RFC8252].

    The operating requirements to be able to use this authorization flow
    are:

    (1)  The device is already connected to the Internet.

    (2)  The device is able to make outbound HTTPS requests.

    (3)  The device is able to display or otherwise communicate a URI and
            code sequence to the user.

    (4)  The user has a secondary device (e.g., personal computer or
            smartphone) from which they can process the request.

    As the device flow does not require two-way communication between the
    OAuth client and the user-agent (unlike other OAuth 2 flows), it
    supports several use cases that cannot be served by those other
    approaches.

    Instead of interacting with the end user's user agent, the client
    instructs the end user to use another computer or device and connect
    to the authorization server to approve the access request.  Since the
    client cannot receive incoming requests, it polls the authorization
    server repeatedly until the end user completes the approval process.

    The device typically chooses the set of authorization servers to
    support (i.e., its own authorization server, or those by providers it
    has relationships with).  It is not uncommon for the device
    application to support only a single authorization server, such as
    with a TV application for a specific media provider that supports
    only that media provider's authorization server.  The user may not
    have an established relationship yet with that authorization
    provider, though one can potentially be set up during the
    authorization flow.

    +----------+                                +----------------+
    |          |>---(A)-- Client Identifier --->|                |
    |          |                                |                |
    |          |<---(B)-- Verification Code, --<|                |
    |          |              User Code,        |                |
    |          |         & Verification URI     |                |
    |  Device  |                                |                |
    |  Client  |         Client Identifier &    |                |
    |          |>---(E)-- Verification Code --->|                |
    |          |    polling...                  |                |
    |          |>---(E)-- Verification Code --->|                |
    |          |                                |  Authorization |
    |          |<---(F)-- Access Token --------<|     Server     |
    +----------+  (w/ Optional Refresh Token)   |                |
            v                                     |                |
            :                                     |                |
        (C) User Code & Verification URI       |                |
            :                                     |                |
            v                                     |                |
    +----------+                                |                |
    | End user |                                |                |
    |    at    |<---(D)-- User authenticates -->|                |
    |  Browser |                                |                |
    +----------+                                +----------------+

                        Figure 1: Device Flow.

    The device flow illustrated in Figure 1 includes the following steps:

    (A) The client requests access from the authorization server and
    includes its client identifier in the request.

    (B) The authorization server issues a verification code, an end-
    user code, and provides the end-user verification URI.

    (C) The client instructs the end user to use its user agent
    (elsewhere) and visit the provided end-user verification URI.  The
    client provides the user with the end-user code to enter in order
    to grant access.

    (D) The authorization server authenticates the end user (via the
    user agent) and prompts the user to grant the client's access
    request.  If the user agrees to the client's access request, the
    user enters the user code provided by the client.  The
    authorization server validates the user code provided by the user.

    (E) While the end user authorizes (or denies) the client's request
    (step D), the client repeatedly polls the authorization server to
    find out if the user completed the user authorization step.  The
    client includes the verification code and its client identifier.

    (F) Assuming the end user granted access, the authorization server
    validates the verification code provided by the client and
    responds back with the access token.

    .. _`Device code grant`: https://tools.ietf.org/html/draft-ietf-oauth-device-flow-13#section-3.1
    """

    def create_authorization_response(self, request, token_handler):
        """
        In response, the authorization server generates a unique device
        verification code and an end-user code that are valid for a limited
        time and includes them in the HTTP response body using the
        "application/json" format [RFC8259] with a 200 (OK) status code.  The
        response contains the following parameters:

        device_code
            REQUIRED.  The device verification code.

        user_code
            REQUIRED.  The end-user verification code.

        verification_uri
            REQUIRED.  The end-user verification URI on the authorization
            server.  The URI should be short and easy to remember as end users
            will be asked to manually type it into their user-agent.

        verification_uri_complete
            OPTIONAL.  A verification URI that includes the "user_code" (or
            other information with the same function as the "user_code"),
            designed for non-textual transmission.

        expires_in
            REQUIRED.  The lifetime in seconds of the "device_code" and
            "user_code".

        interval
            OPTIONAL.  The minimum amount of time in seconds that the client
            SHOULD wait between polling requests to the token endpoint.  If no
            value is provided, clients MUST use 5 as the default.

        For example:

            HTTP/1.1 200 OK
            Content-Type: application/json
            Cache-Control: no-store

            {
                "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.com/device",
                "verification_uri_complete":
                    "https://example.com/device?user_code=WDJB-MJHT",
                "expires_in": 1800,
                "interval": 5
            }
        """
        try:
            self.validate_authorization_request(request)
            log.debug('Pre resource owner authorization validation ok for %r.',
                      request)

        # If the request fails due to the client identifier missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error
        except errors.FatalClientError as e:
            log.debug('Fatal client error during validation of %r. %r.', request, e)
            raise

        # If the resource owner denies the access request or if the request fails
        # the authorization server SHOULD inform the resource owner of the
        # error
        except errors.OAuth2Error as e:
            log.debug('Client error during validation of %r. %r.', request, e)
            raise

        grant = token_handler.create_code(request)
        grant['verification_uri'] = self.request_validator.get_verification_url(request)
        grant['verification_uri_complete'] = self.request_validator.get_verification_url_complete(request, grant)
        grant['interval'] = self.request_validator.get_interval(request)

        log.debug('Created device code grant %r for request %r.',
                  grant, request)

        for modifier in self._code_modifiers:
            grant = modifier(grant, token_handler, request)

        log.debug('Saving grant %r for %r.', grant, request)
        self.request_validator.save_device_code(request.client_id, grant, request)

        return {}, grant, 201

    def create_token_response(self, request, token_handler):
        """
        After displaying instructions to the user, the client makes an Access
        Token Request to the token endpoint (as defined by Section 3.2 of
        [RFC6749]) with a "grant_type" of "urn:ietf:params:oauth:grant-type:device_code".  This is an extension
        grant type (as defined by Section 4.5 of [RFC6749]) created by this
        specification, with the following parameters:

        grant_type
            REQUIRED.  Value MUST be set to
            "urn:ietf:params:oauth:grant-type:device_code".

        device_code
            REQUIRED.  The device verification code, "device_code" from the
            Device Authorization Response, defined in Section 3.2.

        client_id
            REQUIRED, if the client is not authenticating with the
            authorization server as described in Section 3.2.1. of [RFC6749].

        For example, the client makes the following HTTPS request (line
        breaks are for display purposes only):


            POST /token HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded

            grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
            &device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
            &client_id=459691054427


        If the client was issued client credentials (or assigned other
        authentication requirements), the client MUST authenticate with the
        authorization server as described in Section 3.2.1 of [RFC6749].
        Note that there are security implications of statically distributed
        client credentials, see Section 5.6.

        The response to this request is defined in Section 3.5.  Unlike other
        OAuth grant types, it is expected for the client to try the Access
        Token Request repeatedly in a polling fashion, based on the error
        code in the response.

        If the user has approved the grant, the token endpoint responds with
        a success response defined in Section 5.1 of [RFC6749]; otherwise it
        responds with an error, as defined in Section 5.2 of [RFC6749].

        In addition to the error codes defined in Section 5.2 of [RFC6749],
        the following error codes are specified by the device flow for use in
        token endpoint responses:

        authorization_pending
            The authorization request is still pending as the end user hasn't
            yet completed the user interaction steps (Section 3.3).  The
            client SHOULD repeat the Access Token Request to the token
            endpoint (a process known as polling).  Before each new request
            the client MUST wait at least the number of seconds specified by
            the "interval" parameter of the Device Authorization Response (see
            Section 3.2), or 5 seconds if none was provided, and respect any
            increase in the polling interval required by the "slow_down"
            error.

        slow_down
            A variant of "authorization_pending", the authorization request is
            still pending and polling should continue, but the interval MUST
            be increased by 5 seconds for this and all subsequent requests.

        access_denied
            The end user denied the authorization request.

        expired_token
            The "device_code" has expired and the device flow authorization
            session has concluded.  The client MAY commence a new Device
            Authorization Request but SHOULD wait for user interaction before
            restarting to avoid unnecessary polling.

        A client receiving an error response as defined in Section 5.2 of
        [RFC6749] MUST stop polling and SHOULD react accordingly, for
        example, by displaying an error to the user, except for the error
        codes "authorization_pending" and "slow_down" which are processed as
        described above.

        The assumption of this specification is that the secondary device the
        user is authorizing the request on does not have a way to communicate
        back to the OAuth client.  Only a one-way channel is required to make
        this flow useful in many scenarios.  For example, an HTML application
        on a TV that can only make outbound requests.  If a return channel
        were to exist for the chosen user interaction interface, then the
        device MAY wait until notified on that channel that the user has
        completed the action before initiating the token request (as an
        alternative to polling).  Such behavior is, however, outside the
        scope of this specification.
        """
        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        try:
            self.validate_token_request(request)
            log.debug('Token request validation ok for %r.', request)
        except errors.OAuth2Error as e:
            log.debug('Client error during validation of %r. %r.', request, e)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, refresh_token=self.refresh_token, save_token=False)
        for modifier in self._token_modifiers:
            token = modifier(token, token_handler, request)
        self.request_validator.save_token(token, request)
        self.request_validator.invalidate_authorization_code(
            request.client_id, request.code, request)
        return headers, json.dumps(token), 200

    def validate_authorization_request(self, request):

        # First check for fatal errors

        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.

        # First check duplicate parameters
        for param in ('client_id', 'response_type', 'scope', 'state'):
            try:
                duplicate_params = request.duplicate_params
            except ValueError:
                raise errors.InvalidRequestFatalError(description='Unable to parse query string', request=request)
            if param in duplicate_params:
                raise errors.InvalidRequestFatalError(description='Duplicate %s parameter.' % param, request=request)

        # # REQUIRED. The client identifier as described in Section 2.2.
        # # https://tools.ietf.org/html/rfc6749#section-2.2
        if not request.client_id:
            raise errors.MissingClientIdError(request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(request=request)

        # Then check for normal errors.

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the query component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B.
        # https://tools.ietf.org/html/rfc6749#appendix-B

        # Note that the correct parameters to be added are automatically
        # populated through the use of specific exceptions.

        request_info = {}
        for validator in self.custom_validators.pre_auth:
            request_info.update(validator(request))

        # OPTIONAL. The scope of the access request as described by Section 3.3
        # https://tools.ietf.org/html/rfc6749#section-3.3
        self.validate_scopes(request)

        request_info.update({
            'client_id': request.client_id,
            'response_type': request.response_type,
            'request': request
        })

        for validator in self.custom_validators.post_auth:
            request_info.update(validator(request))

        return request.scopes, request_info

    def validate_token_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        
        # REQUIRED. Value MUST be set to "urn:ietf:params:oauth:grant-type:device_code".
        if request.grant_type not in ('urn:ietf:params:oauth:grant-type:device_code'):
            raise errors.UnsupportedGrantTypeError(request=request)

        for validator in self.custom_validators.pre_token:
            validator(request)

        if request.device_code is None:
            raise errors.InvalidRequestError(
                description='Missing device_code parameter.', request=request)

        for param in ('client_id', 'grant_type'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description='Duplicate %s parameter.' % param,
                                                 request=request)

        if self.request_validator.client_authentication_required(request):
            # If the client type is confidential or the client was issued client
            # credentials (or assigned other authentication requirements), the
            # client MUST authenticate with the authorization server as described
            # in Section 3.2.1.
            # https://tools.ietf.org/html/rfc6749#section-3.2.1
            if not self.request_validator.authenticate_client(request):
                log.debug('Client authentication failed, %r.', request)
                raise errors.InvalidClientError(request=request)
        elif not self.request_validator.authenticate_client_id(request.client_id, request):
            # REQUIRED, if the client is not authenticating with the
            # authorization server as described in Section 3.2.1.
            # https://tools.ietf.org/html/rfc6749#section-3.2.1
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)

        if not hasattr(request.client, 'client_id'):
            raise NotImplementedError('Authenticate client must set the '
                                      'request.client.client_id attribute '
                                      'in authenticate_client.')

        request.client_id = request.client_id or request.client.client_id

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        # REQUIRED. The authorization code received from the
        # authorization server.
        if not self.request_validator.validate_device_code(request.client_id,
                                                    request.device_code, request.client, request):
            log.debug('Client, %r (%r), is not allowed access to scopes %r.',
                      request.client_id, request.client, request.scopes)
            raise errors.InvalidGrantError(request=request)

        for attr in ('user', 'scopes'):
            if getattr(request, attr, None) is None:
                log.debug('request.%s was not set on code validation.', attr)

        for validator in self.custom_validators.post_token:
            validator(request)
