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
# from .. import errors

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

    response_types = ['code']
    user_code_length = 6

    def create_authorization_code(self, request):
        """
        Generates an authorization grant represented as a dictionary.
        
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        grant = {
            'device_code': common.generate_token(),
            'user_code': common.generate_token(length=self.user_code_length)
        }

        if hasattr(request, 'state') and request.state:
            grant['state'] = request.state
        log.debug('Created device code grant %r for request %r.',
                  grant, request)
        return grant

    def create_authorization_response(self, request, token_handler):
        """
        The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format, per `Appendix B`_:

        response_type
                REQUIRED.  Value MUST be set to "device_code" for standard OAuth2
                authorization flow.
        client_id
                REQUIRED.  The client identifier as described in `Section 2.2`_.
        scope
                OPTIONAL.  The scope of the access request as described by
                `Section 3.3`_.
        state
                RECOMMENDED.  An opaque value used by the client to maintain
                state between the request and callback.  The authorization
                server includes this value when redirecting the user-agent back
                to the client.  The parameter SHOULD be used for preventing
                cross-site request forgery as described in `Section 10.12`_.

        The client directs the resource owner to the constructed URI using an
        HTTP redirection response, or by other means available to it via the
        user-agent.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.
        :returns: headers, body, status
        :raises: FatalClientError on invalid redirect URI or client id.

        A few examples::

            >>> from your_validator import your_validator
            >>> request = Request('https://example.com/authorize?client_id=valid')
            >>> from oauthlib.common import Request
            >>> from oauthlib.oauth2 import AuthorizationCodeGrant, BearerToken
            >>> token = BearerToken(your_validator)
            >>> grant = AuthorizationCodeGrant(your_validator)
            >>> request.scopes = ['authorized', 'in', 'some', 'form']
            >>> grant.create_authorization_response(request, token)
            (u'http://client.com/?error=invalid_request&error_description=Missing+response_type+parameter.', None, None, 400)
            >>> request = Request('https://example.com/authorize?client_id=valid'
            ...                   '&response_type=code')
            >>> request.scopes = ['authorized', 'in', 'some', 'form']
            >>> grant.create_authorization_response(request, token)
            (u'http://client.com/?code=u3F05aEObJuP2k7DordviIgW5wl52N', None, None, 200)
            >>> # If the client id or redirect uri fails validation
            >>> grant.create_authorization_response(request, token)
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/rfc6749/grant_types.py", line 515, in create_authorization_response
                    >>> grant.create_authorization_response(request, token)
                File "oauthlib/oauth2/rfc6749/grant_types.py", line 591, in validate_authorization_request
            oauthlib.oauth2.rfc6749.errors.InvalidClientIdError

        .. _`Appendix B`: https://tools.ietf.org/html/rfc6749#appendix-B
        .. _`Section 2.2`: https://tools.ietf.org/html/rfc6749#section-2.2
        .. _`Section 3.1.2`: https://tools.ietf.org/html/rfc6749#section-3.1.2
        .. _`Section 3.3`: https://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 10.12`: https://tools.ietf.org/html/rfc6749#section-10.12
        """
        # try:
        #     self.validate_authorization_request(request)
        #     log.debug('Pre resource owner authorization validation ok for %r.',
        #               request)

        # # If the request fails due to a missing, invalid, or mismatching
        # # redirection URI, or if the client identifier is missing or invalid,
        # # the authorization server SHOULD inform the resource owner of the
        # # error and MUST NOT automatically redirect the user-agent to the
        # # invalid redirection URI.
        # except errors.FatalClientError as e:
        #     log.debug('Fatal client error during validation of %r. %r.',
        #               request, e)
        #     raise

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the query component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B:
        # https://tools.ietf.org/html/rfc6749#appendix-B
        # except errors.OAuth2Error as e:
        #     log.debug('Client error during validation of %r. %r.', request, e)
        #     request.redirect_uri = request.redirect_uri or self.error_uri
        #     redirect_uri = common.add_params_to_uri(
        #         request.redirect_uri, e.twotuples,
        #         fragment=request.response_mode == "fragment")
        #     return {'Location': redirect_uri}, None, 302

        grant = self.create_authorization_code(request)
        # for modifier in self._code_modifiers:
        #     grant = modifier(grant, token_handler, request)
        log.debug('Saving grant %r for %r.', grant, request)
        # self.request_validator.save_authorization_code(
        #     request.client_id, grant, request)
        # return self.prepare_authorization_response(
        #     request, grant, {}, None, 302)

    def create_token_response(self, request, token_handler):
        """Validate the authorization code.

        The client MUST NOT use the authorization code more than once. If an
        authorization code is used more than once, the authorization server
        MUST deny the request and SHOULD revoke (when possible) all tokens
        previously issued based on that authorization code. The authorization
        code is bound to the client identifier and redirection URI.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.

        """
        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        # try:
        #     self.validate_token_request(request)
        #     log.debug('Token request validation ok for %r.', request)
        # except errors.OAuth2Error as e:
        #     log.debug('Client error during validation of %r. %r.', request, e)
        #     return headers, e.json, e.status_code

        token = token_handler.create_token(request, refresh_token=self.refresh_token, save_token=False)
        for modifier in self._token_modifiers:
            token = modifier(token, token_handler, request)
        self.request_validator.save_token(token, request)
        self.request_validator.invalidate_authorization_code(
            request.client_id, request.code, request)
        return headers, json.dumps(token), 200

    def validate_authorization_request(self, request):
        """Check the authorization request for normal and fatal errors.

        A normal error could be a missing response_type parameter or the client
        attempting to access scope it is not allowed to ask authorization for.
        Normal errors can safely be included in the redirection URI and
        sent back to the client.

        Fatal errors occur when the client_id or redirect_uri is invalid or
        missing. These must be caught by the provider and handled, how this
        is done is outside of the scope of OAuthLib but showing an error
        page describing the issue is a good idea.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """

        # First check for fatal errors

        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.

        # First check duplicate parameters
        # for param in ('client_id', 'response_type', 'redirect_uri', 'scope', 'state'):
        #     try:
        #         duplicate_params = request.duplicate_params
        #     except ValueError:
        #         raise errors.InvalidRequestFatalError(description='Unable to parse query string', request=request)
        #     if param in duplicate_params:
        #         raise errors.InvalidRequestFatalError(description='Duplicate %s parameter.' % param, request=request)

        # # REQUIRED. The client identifier as described in Section 2.2.
        # # https://tools.ietf.org/html/rfc6749#section-2.2
        # if not request.client_id:
        #     raise errors.MissingClientIdError(request=request)

        # if not self.request_validator.validate_client_id(request.client_id, request):
        #     raise errors.InvalidClientIdError(request=request)

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
        # for validator in self.custom_validators.pre_auth:
        #     request_info.update(validator(request))

        # REQUIRED.
        # if request.response_type is None:
        #     raise errors.MissingResponseTypeError(request=request)
        # # Value MUST be set to "code" or one of the OpenID authorization code including
        # # response_types "code token", "code id_token", "code token id_token"
        # elif not 'code' in request.response_type and request.response_type != 'none':
        #     raise errors.UnsupportedResponseTypeError(request=request)

        # if not self.request_validator.validate_response_type(request.client_id,
        #                                                      request.response_type,
        #                                                      request.client, request):

        #     log.debug('Client %s is not authorized to use response_type %s.',
        #               request.client_id, request.response_type)
        #     raise errors.UnauthorizedClientError(request=request)

        # OPTIONAL. The scope of the access request as described by Section 3.3
        # https://tools.ietf.org/html/rfc6749#section-3.3
        self.validate_scopes(request)

        request_info.update({
            'client_id': request.client_id,
            'response_type': request.response_type,
            'state': request.state,
            'request': request
        })

        # for validator in self.custom_validators.post_auth:
        #     request_info.update(validator(request))

        return request.scopes, request_info

    def validate_token_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        # REQUIRED. Value MUST be set to "authorization_code".
        # if request.grant_type not in ('authorization_code', 'openid'):
        #     raise errors.UnsupportedGrantTypeError(request=request)

        # for validator in self.custom_validators.pre_token:
        #     validator(request)

        # if request.code is None:
        #     raise errors.InvalidRequestError(
        #         description='Missing code parameter.', request=request)

        # for param in ('client_id', 'grant_type'):
        #     if param in request.duplicate_params:
        #         raise errors.InvalidRequestError(description='Duplicate %s parameter.' % param,
        #                                          request=request)

        # if self.request_validator.client_authentication_required(request):
        #     # If the client type is confidential or the client was issued client
        #     # credentials (or assigned other authentication requirements), the
        #     # client MUST authenticate with the authorization server as described
        #     # in Section 3.2.1.
        #     # https://tools.ietf.org/html/rfc6749#section-3.2.1
        #     if not self.request_validator.authenticate_client(request):
        #         log.debug('Client authentication failed, %r.', request)
        #         raise errors.InvalidClientError(request=request)
        # elif not self.request_validator.authenticate_client_id(request.client_id, request):
        #     # REQUIRED, if the client is not authenticating with the
        #     # authorization server as described in Section 3.2.1.
        #     # https://tools.ietf.org/html/rfc6749#section-3.2.1
        #     log.debug('Client authentication failed, %r.', request)
        #     raise errors.InvalidClientError(request=request)

        if not hasattr(request.client, 'client_id'):
            raise NotImplementedError('Authenticate client must set the '
                                      'request.client.client_id attribute '
                                      'in authenticate_client.')

        request.client_id = request.client_id or request.client.client_id

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        # REQUIRED. The authorization code received from the
        # authorization server.
        # if not self.request_validator.validate_code(request.client_id,
        #                                             request.code, request.client, request):
        #     log.debug('Client, %r (%r), is not allowed access to scopes %r.',
        #               request.client_id, request.client, request.scopes)
        #     raise errors.InvalidGrantError(request=request)

        for attr in ('user', 'scopes'):
            if getattr(request, attr, None) is None:
                log.debug('request.%s was not set on code validation.', attr)

        # for validator in self.custom_validators.post_token:
        #     validator(request)
