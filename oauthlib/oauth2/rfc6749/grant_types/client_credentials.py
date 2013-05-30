# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc6749.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import unicode_literals, absolute_import
import json
from oauthlib.common import log

from .base import GrantTypeBase
from .. import errors
from ..request_validator import RequestValidator


class ClientCredentialsGrant(GrantTypeBase):
    """`Client Credentials Grant`_

    The client can request an access token using only its client
    credentials (or other supported means of authentication) when the
    client is requesting access to the protected resources under its
    control, or those of another resource owner that have been previously
    arranged with the authorization server (the method of which is beyond
    the scope of this specification).

    The client credentials grant type MUST only be used by confidential
    clients::

        +---------+                                  +---------------+
        :         :                                  :               :
        :         :>-- A - Client Authentication --->: Authorization :
        : Client  :                                  :     Server    :
        :         :<-- B ---- Access Token ---------<:               :
        :         :                                  :               :
        +---------+                                  +---------------+

    Figure 6: Client Credentials Flow

    The flow illustrated in Figure 6 includes the following steps:

    (A)  The client authenticates with the authorization server and
            requests an access token from the token endpoint.

    (B)  The authorization server authenticates the client, and if valid,
            issues an access token.

    .. _`Client Credentials Grant`: http://tools.ietf.org/html/rfc6749#section-4.4
    """

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_token_response(self, request, token_handler):
        """Return token or error in JSON format.

        If the access token request is valid and authorized, the
        authorization server issues an access token as described in
        `Section 5.1`_.  A refresh token SHOULD NOT be included.  If the request
        failed client authentication or is invalid, the authorization server
        returns an error response as described in `Section 5.2`_.

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        """
        try:
            log.debug('Validating access token request, %r.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            log.debug('Client error in token request. %s.', e)
            return None, {}, e.json, e.status_code

        token = token_handler.create_token(request, refresh_token=False)
        log.debug('Issuing token to client id %r (%r), %r.',
                  request.client_id, request.client, token)
        return None, {}, json.dumps(token), 200

    def validate_token_request(self, request):
        if not getattr(request, 'grant_type'):
            raise errors.InvalidRequestError('Request is missing grant type.',
                                             request=request)

        if not request.grant_type == 'client_credentials':
            raise errors.UnsupportedGrantTypeError(request=request)

        for param in ('grant_type', 'scope'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(state=request.state,
                        description='Duplicate %s parameter.' % param,
                        request=request)

        log.debug('Authenticating client, %r.', request)
        if not self.request_validator.authenticate_client(request):
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)
        else:
            if not hasattr(request.client, 'client_id'):
                raise NotImplementedError('Authenticate client must set the '
                                          'request.client.client_id attribute '
                                          'in authenticate_client.')
        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        log.debug('Authorizing access to user %r.', request.user)
        request.client_id = request.client_id or request.client.client_id
        self.validate_scopes(request)


class RefreshTokenGrant(GrantTypeBase):
    """`Refresh token grant`_

    .. _`Refresh token grant`: http://tools.ietf.org/html/rfc6749#section-6
    """

    @property
    def issue_new_refresh_tokens(self):
        return True

    def __init__(self, request_validator=None, issue_new_refresh_tokens=True):
        self.request_validator = request_validator or RequestValidator()

    def create_token_response(self, request, token_handler):
        """Create a new access token from a refresh_token.

        If valid and authorized, the authorization server issues an access
        token as described in `Section 5.1`_. If the request failed
        verification or is invalid, the authorization server returns an error
        response as described in `Section 5.2`_.

        The authorization server MAY issue a new refresh token, in which case
        the client MUST discard the old refresh token and replace it with the
        new refresh token. The authorization server MAY revoke the old
        refresh token after issuing a new refresh token to the client. If a
        new refresh token is issued, the refresh token scope MUST be
        identical to that of the refresh token included by the client in the
        request.

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        """
        headers = {
                'Content-Type': 'application/json;charset=UTF-8',
                'Cache-Control': 'no-store',
                'Pragma': 'no-cache',
        }
        try:
            log.debug('Validating refresh token request, %r.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return None, headers, e.json, 400

        token = token_handler.create_token(request,
                refresh_token=self.issue_new_refresh_tokens)
        log.debug('Issuing new token to client id %r (%r), %r.',
                  request.client_id, request.client, token)
        return None, headers, json.dumps(token), 200

    def validate_token_request(self, request):
        # REQUIRED. Value MUST be set to "refresh_token".
        if request.grant_type != 'refresh_token':
            raise errors.UnsupportedGrantTypeError(request=request)

        if request.refresh_token is None:
            raise errors.InvalidRequestError(
                    description='Missing refresh token parameter.',
                    request=request)

        # Because refresh tokens are typically long-lasting credentials used to
        # request additional access tokens, the refresh token is bound to the
        # client to which it was issued.  If the client type is confidential or
        # the client was issued client credentials (or assigned other
        # authentication requirements), the client MUST authenticate with the
        # authorization server as described in Section 3.2.1.
        # http://tools.ietf.org/html/rfc6749#section-3.2.1
        log.debug('Authenticating client, %r.', request)
        if not self.request_validator.authenticate_client(request):
            log.debug('Invalid client (%r), denying access.', request)
            raise errors.AccessDeniedError(request=request)

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        # OPTIONAL. The scope of the access request as described by
        # Section 3.3. The requested scope MUST NOT include any scope
        # not originally granted by the resource owner, and if omitted is
        # treated as equal to the scope originally granted by the
        # resource owner.
        if request.scopes:
            log.debug('Ensuring refresh token %s has access to scopes %r.',
                    request.refresh_token, request.scopes)
        else:
            log.debug('Reusing scopes from previous access token.')
        if not self.request_validator.confirm_scopes(request.refresh_token,
                request.scopes, request):
            log.debug('Refresh token %s lack requested scopes, %r.',
                      request.refresh_token, request.scopes)
            raise errors.InvalidScopeError(state=request.state, request=request)

        # REQUIRED. The refresh token issued to the client.
        log.debug('Validating refresh token %s for client %r.',
                  request.refresh_token, request.client)
        if not self.request_validator.validate_refresh_token(
                request.refresh_token, request.client, request):
            log.debug('Invalid refresh token, %s, for client %r.',
                      request.refresh_token, request.client)
            raise errors.InvalidRequestError(request=request)
