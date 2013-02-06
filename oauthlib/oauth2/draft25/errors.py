# coding=utf-8
"""
oauthlib.oauth2.draft_25.errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import unicode_literals
import json
from oauthlib.common import urlencode, add_params_to_uri


class OAuth2Error(Exception):
    error = None

    def __init__(self, description=None, uri=None, state=None, status_code=400):
        """
        description:    A human-readable ASCII [USASCII] text providing
                        additional information, used to assist the client
                        developer in understanding the error that occurred.
                        Values for the "error_description" parameter MUST NOT
                        include characters outside the set
                        x20-21 / x23-5B / x5D-7E.

        uri:    A URI identifying a human-readable web page with information
                about the error, used to provide the client developer with
                additional information about the error.  Values for the
                "error_uri" parameter MUST conform to the URI- Reference
                syntax, and thus MUST NOT include characters outside the set
                x21 / x23-5B / x5D-7E.

        state:  A CSRF protection value received from the client.
        """
        self.description = description
        self.uri = uri
        self.state = state
        self.status_code = status_code

    def in_uri(self, uri):
        return add_params_to_uri(uri, self.twotuples)

    @property
    def twotuples(self):
        error = [('error', self.error)]
        if self.description:
            error.append(('error_description', self.description))
        if self.uri:
            error.append(('error_uri', self.uri))
        if self.state:
            error.append(('state', self.state))
        return error

    @property
    def urlencoded(self):
        return urlencode(self.twotuples)

    @property
    def json(self):
        return json.dumps(dict(self.twotuples))


class FatalClientError(OAuth2Error):
    pass


class InvalidRedirectURIError(FatalClientError):
    error = 'invalid_redirect_uri'


class MissingRedirectURIError(FatalClientError):
    error = 'missing_redirect_uri'


class MismatchingRedirectURIError(FatalClientError):
    error = 'mismatching_redirect_uri'


class MissingClientIdError(FatalClientError):
    error = 'invalid_client_id'


class InvalidClientIdError(FatalClientError):
    error = 'invalid_client_id'


class InvalidRequestError(OAuth2Error):
    """The request is missing a required parameter, includes an invalid
    parameter value, includes a parameter more than once, or is
    otherwise malformed.
    """
    error = 'invalid_request'


class UnauthorizedClientError(OAuth2Error):
    """The client is not authorized to request an authorization code using
    this method.
    """
    error = 'unauthorized_client'


class AccessDeniedError(OAuth2Error):
    """The resource owner or authorization server denied the request."""
    error = 'access_denied'


class UnsupportedResponseTypeError(OAuth2Error):
    """The authorization server does not support obtaining an authorization
    code using this method.
    """
    error = 'unsupported_response_type'


class InvalidScopeError(OAuth2Error):
    """The requested scope is invalid, unknown, or malformed."""
    error = 'invalid_scope'


class ServerError(OAuth2Error):
    """The authorization server encountered an unexpected condition that
    prevented it from fulfilling the request.  (This error code is needed
    because a 500 Internal Server Error HTTP status code cannot be returned
    to the client via a HTTP redirect.)
    """
    error = 'server_error'


class TemporarilyUnavailableError(OAuth2Error):
    """The authorization server is currently unable to handle the request
    due to a temporary overloading or maintenance of the server.
    (This error code is needed because a 503 Service Unavailable HTTP
    status code cannot be returned to the client via a HTTP redirect.)
    """
    error = 'temporarily_unavailable'


class InvalidClientError(OAuth2Error):
    """Client authentication failed (e.g. unknown client, no client
    authentication included, or unsupported authentication method).
    The authorization server MAY return an HTTP 401 (Unauthorized) status
    code to indicate which HTTP authentication schemes are supported.
    If the client attempted to authenticate via the "Authorization" request
    header field, the authorization server MUST respond with an
    HTTP 401 (Unauthorized) status code, and include the "WWW-Authenticate"
    response header field matching the authentication scheme used by the
    client.
    """
    error = 'invalid_client'


class InvalidGrantError(OAuth2Error):
    """The provided authorization grant (e.g. authorization code, resource
    owner credentials) or refresh token is invalid, expired, revoked, does
    not match the redirection URI used in the authorization request, or was
    issued to another client.
    """
    error = 'invalid_grant'


class UnauthorizedClientError(OAuth2Error):
    """The authenticated client is not authorized to use this authorization
    grant type.
    """
    error = 'unauthorized_client'


class UnsupportedGrantTypeError(OAuth2Error):
    """The authorization grant type is not supported by the authorization
    server.
    """
    error = 'unsupported_grant_type'


class InvalidScopeError(OAuth2Error):
    """The requested scope is invalid, unknown, malformed, or exceeds the
    scope granted by the resource owner.
    """
    error = 'invalid_scope'
