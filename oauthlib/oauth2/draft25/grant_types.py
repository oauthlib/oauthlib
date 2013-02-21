# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.draft_25.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import unicode_literals
import json
import logging
from oauthlib import common
from oauthlib.oauth2.draft25 import errors, utils
from oauthlib.uri_validate import is_absolute_uri

log = logging.getLogger('oauthlib')


class RequestValidator(object):

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate client through means outside the OAuth 2 spec.

        Means of authentication is negotiated beforehand and may for example
        be `HTTP Basic Authentication Scheme`_ which utilizes the Authorization
        header.

        Headers may be accesses through request.headers and parameters found in
        both body and query can be obtained by direct attribute access, i.e.
        request.client_id for client_id in the URL query.

        OBS! Certain grant types rely on this authentication, possibly with
        other fallbacks, and for them to recognize this authorization please
        set the client attribute on the request (request.client). Note that
        preferably this client object should have a client_id attribute of
        unicode type (request.client.client_id).

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant (may be disabled)
            - Client Credentials Grant
            - Refresh Token Grant

        .. _`HTTP Basic Authentication Scheme`: http://tools.ietf.org/html/rfc1945#section-11.1
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a non-confidential client.

        A non-confidential client is one that is not required to authenticate
        through other means, such as using HTTP Basic.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri requested.

        If the client specifies a redirect_uri when obtaining code then
        that redirect URI must be bound to the code and verified equal
        in this method.

        All clients should register the absolute URIs of all URIs they intend
        to redirect to. The registration is outside of the scope of oauthlib.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization_code.
        :param redirect_uri: Unicode absolute URI
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (during token request)
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        """Ensure the refresh token is authorized access to requested scopes.

        :param refresh_token: Unicode refresh token
        :param scopes: List of scopes (defined by you)
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Refresh token grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Get the default redirect URI for the client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Get the default scopes for the client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of default scopes

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Persist the authorization_code.

        The code should at minimum be associated with:
            - a client and it's client_id
            - the redirect URI used (request.redirect_uri)
            - whether the redirect URI used is the client default or not
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)

        The authorization code grant dict (code) holds at least the key 'code',
        {'code': 'sdf345jsdf0934f'}.

        :param client_id: Unicode client identifier
        :param code: A dict of the authorization code grant.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token.

        The Bearer token should at minimum be associated with:
            - a client and it's client_id, if available
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)
            - an expiration time
            - a refresh token, if issued

        The Bearer token dict may hold a number of items,
        {
            'token_type': 'Bearer',
            'token': 'askfjh234as9sd8',
            'expires_in': 3600,
            'scope': ['list', 'of', 'authorized', 'scopes'],
            'refresh_token': '23sdf876234',  # if issued
            'state': 'given_by_client',  # if supplied by client
        }

        :param client_id: Unicode client identifier
        :param token: A Bearer token dict
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by all core grant types issuing Bearer tokens:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant (might not associate a client)
            - Client Credentials grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_bearer_token(self, token, scopes, request):
        """Ensure the Bearer token is valid and authorized access to scopes.

        Note, the request.user attribute can be set to the resource owner
        associated with this token. Similarly the request.client and
        request.scopes attribute can be set to associated client object
        and authorized scopes. If you then use a decorator such as the
        one provided for django these attributes will be made available
        in all protected views as keyword arguments.

        :param token: Unicode Bearer token
        :param scopes: List of scopes (defined by you)
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is indirectly used by all core Bearer token issuing grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_code(self, client_id, code, client, *args, **kwargs):
        """Ensure the authorization_code is valid and assigned to client.

        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes and
        request.state must also be set.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization code
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        """Ensure client is authorized to use the grant_type requested.

        :param client_id: Unicode client identifier
        :param grant_type: Unicode grant type, i.e. authorization_code, password.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
            - Refresh Token Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri requested.

        All clients should register the absolute URIs of all URIs they intend
        to redirect to. The registration is outside of the scope of oauthlib.

        :param client_id: Unicode client identifier
        :param redirect_uri: Unicode absolute URI
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Ensure the Bearer token is valid and authorized access to scopes.

        OBS! The request.user attribute should be set to the resource owner
        associated with this refresh token.

        :param refresh_token: Unicode refresh token
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (indirectly by issuing refresh tokens)
            - Resource Owner Password Credentials Grant (also indirectly)
            - Refresh Token Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        """Ensure client is authorized to use the grant_type requested.

        :param client_id: Unicode client identifier
        :param response_type: Unicode response type, i.e. code, token.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """Ensure the client is authorized access to requested scopes.

        :param client_id: Unicode client identifier
        :param scopes: List of scopes (defined by you)
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """Ensure the username and password is valid.

        OBS! The validation should also set the user attribute of the request
        to a valid resource owner, i.e. request.user = username or similar. If
        not set you will be unable to associate a token with a user in the
        persistance method used (commonly, save_bearer_token).

        :param username: Unicode username
        :param password: Unicode password
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Resource Owner Password Credentials Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')


class GrantTypeBase(object):
    error_uri = None
    request_validator = None

    def create_authorization_response(self, request, token_handler):
        raise NotImplementedError('Subclasses must implement this method.')

    def create_token_response(self, request, token_handler):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_grant_type(self, request):
        if not self.request_validator.validate_grant_type(request.client_id,
                request.grant_type, request.client, request):
            log.debug('Unauthorized from %r (%r) access to grant type %s.',
                      request.client_id, request.client, request.grant_type)
            raise errors.UnauthorizedClientError()

    def validate_scopes(self, request):
        request.scopes = utils.scope_to_list(request.scope) or utils.scope_to_list(
                self.request_validator.get_default_scopes(request.client_id, request))
        log.debug('Validating access to scopes %r for client %r (%r).',
                  request.scopes, request.client_id, request.client)
        if not self.request_validator.validate_scopes(request.client_id,
                request.scopes, request.client, request):
            raise errors.InvalidScopeError(state=request.state)


class AuthorizationCodeGrant(GrantTypeBase):

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_authorization_code(self, request):
        """Generates an authorization grant represented as a dictionary."""
        grant = {'code': common.generate_token()}
        if hasattr(request, 'state') and request.state:
            grant['state'] = request.state
        log.debug('Created authorization code grant %r for request %r.',
                  grant, request)
        return grant

    def create_authorization_response(self, request, token_handler):
        try:
            self.validate_authorization_request(request)
            log.debug('Pre resource owner authorization validation ok for %r.',
                      request)

        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.
        except errors.FatalClientError as e:
            log.debug('Fatal client error during validation of %r. %r.',
                      request, e)
            raise

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the query component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B:
        # http://tools.ietf.org/html/rfc6749#appendix-B
        except errors.OAuth2Error as e:
            log.debug('Client error during validation of %r. %r.', request, e)
            request.redirect_uri = request.redirect_uri or self.error_uri
            return common.add_params_to_uri(request.redirect_uri, e.twotuples), None, None, e.status_code

        grant = self.create_authorization_code(request)
        logging.debug('Saving grant %r for %r.', grant, request)
        self.request_validator.save_authorization_code(request, grant)
        return common.add_params_to_uri(request.redirect_uri, grant.items()), None, None, 200

    def create_token_response(self, request, token_handler):
        """Validate the authorization code.

        The client MUST NOT use the authorization code more than once. If an
        authorization code is used more than once, the authorization server
        MUST deny the request and SHOULD revoke (when possible) all tokens
        previously issued based on that authorization code. The authorization
        code is bound to the client identifier and redirection URI.
        """
        try:
            self.validate_token_request(request)
            log.debug('Token request validation ok for %r.', request)
        except errors.OAuth2Error as e:
            log.debug('Client error during validation of %r. %r.', request, e)
            return None, {}, e.json, e.status_code

        return None, {}, json.dumps(token_handler.create_token(request, refresh_token=True)), 200

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
        """

        # First check for fatal errors

        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.

        # REQUIRED. The client identifier as described in Section 2.2.
        # http://tools.ietf.org/html/rfc6749#section-2.2
        if not request.client_id:
            raise errors.MissingClientIdError(state=request.state)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(state=request.state)

        # OPTIONAL. As described in Section 3.1.2.
        # http://tools.ietf.org/html/rfc6749#section-3.1.2
        log.debug('Validating redirection uri %s for client %s.',
                  request.redirect_uri, request.client_id)
        if request.redirect_uri is not None:
            request.using_default_redirect_uri = False
            log.debug('Using provided redirect_uri %s', request.redirect_uri)
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(state=request.state)

            if not self.request_validator.validate_redirect_uri(
                    request.client_id, request.redirect_uri):
                raise errors.MismatchingRedirectURIError(state=request.state)
        else:
            request.redirect_uri = self.request_validator.get_default_redirect_uri(
                    request.client_id, request)
            request.using_default_redirect_uri = True
            log.debug('Using default redirect_uri %s.', request.redirect_uri)
            if not request.redirect_uri:
                raise errors.MissingRedirectURIError(state=request.state)

        # Then check for normal errors.

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the query component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B.
        # http://tools.ietf.org/html/rfc6749#appendix-B

        # Note that the correct parameters to be added are automatically
        # populated through the use of specific exceptions.
        if request.response_type is None:
            raise errors.InvalidRequestError(state=request.state,
                    description='Missing response_type parameter.')

        if not self.request_validator.validate_response_type(request.client_id,
                request.response_type, request):
            log.debug('Client %s is not authorized to use response_type %s.',
                      request.client_id, request.response_type)
            raise errors.UnauthorizedClientError()

        # REQUIRED. Value MUST be set to "code".
        if request.response_type != 'code':
            raise errors.UnsupportedResponseTypeError(state=request.state)

        # OPTIONAL. The scope of the access request as described by Section 3.3
        # http://tools.ietf.org/html/rfc6749#section-3.3
        self.validate_scopes(request)

        return request.scopes, {
                'client_id': request.client_id,
                'redirect_uri': request.redirect_uri,
                'response_type': request.response_type,
        }

    def validate_token_request(self, request):
        # REQUIRED. Value MUST be set to "authorization_code".
        if request.grant_type != 'authorization_code':
            raise errors.UnsupportedGrantTypeError()

        if request.code is None:
            raise errors.InvalidRequestError(
                    description='Missing code parameter.')

        # If the client type is confidential or the client was issued client
        # credentials (or assigned other authentication requirements), the
        # client MUST authenticate with the authorization server as described
        # in Section 3.2.1.
        # http://tools.ietf.org/html/rfc6749#section-3.2.1
        if not self.request_validator.authenticate_client(request):
            # REQUIRED, if the client is not authenticating with the
            # authorization server as described in Section 3.2.1.
            # http://tools.ietf.org/html/rfc6749#section-3.2.1
            if not self.request_validator.authenticate_client_id(
                    request.client_id, request):
                log.debug('Client authentication failed, %r.', request)
                raise errors.InvalidClientError()
        else:
            if not hasattr(request.client, 'client_id'):
                raise NotImplementedError('Authenticate client must set the '
                                          'request.client.client_id attribute '
                                          'in authenticate_client.')

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        # REQUIRED. The authorization code received from the
        # authorization server.
        if not self.request_validator.validate_code(request.client_id,
                request.code, request.client, request):
            log.debug('Client, %r (%r), is not allowed access to scopes %r.',
                      request.client_id, request.client, request.scopes)
            raise errors.InvalidGrantError()

        # REQUIRED, if the "redirect_uri" parameter was included in the
        # authorization request as described in Section 4.1.1, and their
        # values MUST be identical.
        if not self.request_validator.confirm_redirect_uri(request.client_id,
                request.code, request.redirect_uri, request.client):
            log.debug('Redirect_uri (%r) invalid for client %r (%r).',
                      request.redirect_uri, request.client_id, request.client)
            raise errors.AccessDeniedError()


class ImplicitGrant(GrantTypeBase):
    """`Implicit Grant`_

    The implicit grant type is used to obtain access tokens (it does not
    support the issuance of refresh tokens) and is optimized for public
    clients known to operate a particular redirection URI.  These clients
    are typically implemented in a browser using a scripting language
    such as JavaScript.

    Unlike the authorization code grant type, in which the client makes
    separate requests for authorization and for an access token, the
    client receives the access token as the result of the authorization
    request.

    The implicit grant type does not include client authentication, and
    relies on the presence of the resource owner and the registration of
    the redirection URI.  Because the access token is encoded into the
    redirection URI, it may be exposed to the resource owner and other
    applications residing on the same device.

    See `Sections 10.3`_ and `10.16`_ for important security considerations
    when using the implicit grant.

    The client constructs the request URI by adding the following
    parameters to the query component of the authorization endpoint URI
    using the "application/x-www-form-urlencoded" format, per `Appendix B`_:

    response_type
            REQUIRED.  Value MUST be set to "token".

    client_id
            REQUIRED.  The client identifier as described in `Section 2.2`_.

    redirect_uri
            OPTIONAL.  As described in `Section 3.1.2`_.

    scope
            OPTIONAL.  The scope of the access request as described by
            `Section 3.3`_.

    state
            RECOMMENDED.  An opaque value used by the client to maintain
            state between the request and callback.  The authorization
            server includes this value when redirecting the user-agent back
            to the client.  The parameter SHOULD be used for preventing
            cross-site request forgery as described in `Section 10.12`_.

    The authorization server validates the request to ensure that all
    required parameters are present and valid.  The authorization server
    MUST verify that the redirection URI to which it will redirect the
    access token matches a redirection URI registered by the client as
    described in `Section 3.1.2`_.

    .. _`Implicit Grant`: http://tools.ietf.org/html/rfc6749#section-4.2
    .. _`10.16`: http://tools.ietf.org/html/rfc6749#section-10.16
    .. _`Section 2.2`: http://tools.ietf.org/html/rfc6749#section-2.2
    .. _`Section 3.1.2`: http://tools.ietf.org/html/rfc6749#section-3.1.2
    .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
    .. _`Section 10.3`: http://tools.ietf.org/html/rfc6749#section-10.3
    .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
    """

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_authorization_response(self, request, token_handler):
        return self.create_token_response(request, token_handler)

    def create_token_response(self, request, token_handler):
        """Return token or error embedded in the URI fragment.

        If the resource owner grants the access request, the authorization
        server issues an access token and delivers it to the client by adding
        the following parameters to the fragment component of the redirection
        URI using the "application/x-www-form-urlencoded" format, per
        `Appendix B`_:

        access_token
                REQUIRED.  The access token issued by the authorization server.

        token_type
                REQUIRED.  The type of the token issued as described in
                `Section 7.1`_.  Value is case insensitive.

        expires_in
                RECOMMENDED.  The lifetime in seconds of the access token.  For
                example, the value "3600" denotes that the access token will
                expire in one hour from the time the response was generated.
                If omitted, the authorization server SHOULD provide the
                expiration time via other means or document the default value.

        scope
                OPTIONAL, if identical to the scope requested by the client;
                otherwise, REQUIRED.  The scope of the access token as
                described by `Section 3.3`_.

        state
                REQUIRED if the "state" parameter was present in the client
                authorization request.  The exact value received from the
                client.

        The authorization server MUST NOT issue a refresh token.

        .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 7.2`: http://tools.ietf.org/html/rfc6749#section-7.2
        """
        try:
            self.validate_token_request(request)

        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.
        except errors.FatalClientError as e:
            log.debug('Fatal client error during validation of %r. %r.',
                      request, e)
            raise

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the fragment component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B:
        # http://tools.ietf.org/html/rfc6749#appendix-B
        except errors.OAuth2Error as e:
            log.debug('Client error during validation of %r. %r.', request, e)
            return common.add_params_to_uri(request.redirect_uri, e.twotuples,
                    fragment=True), {}, None, e.status_code

        token = token_handler.create_token(request, refresh_token=False)
        return common.add_params_to_uri(request.redirect_uri, token.items(),
                fragment=True), {}, None, 200

    def validate_authorization_request(self, request):
        return self.validate_token_request(request)

    def validate_token_request(self, request):
        """Check the token request for normal and fatal errors.

        This method is very similar to validate_authorization_request in
        the AuthorizationCodeGrant but differ in a few subtle areas.

        A normal error could be a missing response_type parameter or the client
        attempting to access scope it is not allowed to ask authorization for.
        Normal errors can safely be included in the redirection URI and
        sent back to the client.

        Fatal errors occur when the client_id or redirect_uri is invalid or
        missing. These must be caught by the provider and handled, how this
        is done is outside of the scope of OAuthLib but showing an error
        page describing the issue is a good idea.
        """

        # First check for fatal errors

        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.

        # REQUIRED. The client identifier as described in Section 2.2.
        # http://tools.ietf.org/html/rfc6749#section-2.2
        if not request.client_id:
            raise errors.MissingClientIdError(state=request.state)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(state=request.state)

        # OPTIONAL. As described in Section 3.1.2.
        # http://tools.ietf.org/html/rfc6749#section-3.1.2
        if request.redirect_uri is not None:
            request.using_default_redirect_uri = False
            log.debug('Using provided redirect_uri %s', request.redirect_uri)
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(state=request.state)

            # The authorization server MUST verify that the redirection URI
            # to which it will redirect the access token matches a
            # redirection URI registered by the client as described in
            # Section 3.1.2.
            # http://tools.ietf.org/html/rfc6749#section-3.1.2
            if not self.request_validator.validate_redirect_uri(
                    request.client_id, request.redirect_uri):
                raise errors.MismatchingRedirectURIError(state=request.state)
        else:
            request.redirect_uri = self.request_validator.get_default_redirect_uri(
                    request.client_id, request)
            request.using_default_redirect_uri = True
            log.debug('Using default redirect_uri %s.', request.redirect_uri)
            if not request.redirect_uri:
                raise errors.MissingRedirectURIError(state=request.state)
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(state=request.state)

        # Then check for normal errors.

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the fragment component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B.
        # http://tools.ietf.org/html/rfc6749#appendix-B

        # Note that the correct parameters to be added are automatically
        # populated through the use of specific exceptions.
        if request.response_type is None:
            raise errors.InvalidRequestError(state=request.state,
                    description='Missing response_type parameter.')

        # REQUIRED. Value MUST be set to "token".
        if request.response_type != 'token':
            raise errors.UnsupportedResponseTypeError(state=request.state)

        log.debug('Validating use of response_type token for client %r (%r).',
                  request.client_id, request.client)
        if not self.request_validator.validate_response_type(request.client_id,
                request.response_type, request):
            log.debug('Client %s is not authorized to use response_type %s.',
                      request.client_id, request.response_type)
            raise errors.UnauthorizedClientError()

        # OPTIONAL. The scope of the access request as described by Section 3.3
        # http://tools.ietf.org/html/rfc6749#section-3.3
        self.validate_scopes(request)

        return request.scopes, {
                'client_id': request.client_id,
                'redirect_uri': request.redirect_uri,
                'response_type': request.response_type,
        }


class ResourceOwnerPasswordCredentialsGrant(GrantTypeBase):
    """`Resource Owner Password Credentials Grant`_

    The client makes a request to the token endpoint by adding the
    following parameters using the "application/x-www-form-urlencoded"
    format per Appendix B with a character encoding of UTF-8 in the HTTP
    request entity-body:

    grant_type
            REQUIRED.  Value MUST be set to "password".

    username
            REQUIRED.  The resource owner username.

    password
            REQUIRED.  The resource owner password.

    scope
            OPTIONAL.  The scope of the access request as described by
            `Section 3.3`_.

    If the client type is confidential or the client was issued client
    credentials (or assigned other authentication requirements), the
    client MUST authenticate with the authorization server as described
    in `Section 3.2.1`_.

    For example, the client makes the following HTTP request using
    transport-layer security (with extra line breaks for display purposes
    only):

        POST /token HTTP/1.1
        Host: server.example.com
        Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        Content-Type: application/x-www-form-urlencoded

        grant_type=password&username=johndoe&password=A3ddj3w

    The authorization server MUST:

    o  require client authentication for confidential clients or for any
        client that was issued client credentials (or with other
        authentication requirements),

    o  authenticate the client if client authentication is included, and

    o  validate the resource owner password credentials using its
        existing password validation algorithm.

    Since this access token request utilizes the resource owner's
    password, the authorization server MUST protect the endpoint against
    brute force attacks (e.g., using rate-limitation or generating
    alerts).

    .. _`Resource Owner Password Credentials Grant`: http://tools.ietf.org/html/rfc6749#section-4.3
    .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
    .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
    """

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_token_response(self, request, token_handler,
            require_authentication=True):
        """Return token or error in json format.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request failed client
        authentication or is invalid, the authorization server returns an
        error response as described in `Section 5.2`_.

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        """
        try:
            if require_authentication:
                log.debug('Authenticating client, %r.', request)
                if not self.request_validator.authenticate_client(request):
                    log.debug('Client authentication failed, %r.', request)
                    raise errors.InvalidClientError()
                else:
                    if not hasattr(request.client, 'client_id'):
                        raise NotImplementedError(
                                'Authenticate client must set the '
                                'request.client.client_id attribute '
                                'in authenticate_client.')
            else:
                log.debug('Client authentication disabled, %r.', request)
            log.debug('Validating access token request, %r.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            log.debug('Client error in token request, %s.', e)
            return None, {}, e.json, e.status_code

        token = token_handler.create_token(request, refresh_token=True)
        log.debug('Issuing token %r to client id %r (%r) and username %s.',
                  token, request.client_id, request.client, request.username)
        return None, {}, json.dumps(token), 200

    def validate_token_request(self, request):
        for param in ('grant_type', 'username', 'password'):
            if not getattr(request, param):
                raise errors.InvalidRequestError(
                        'Request is missing %s parameter.' % param)

        # This error should rarely (if ever) occur if requests are routed to
        # grant type handlers based on the grant_type parameter.
        if not request.grant_type == 'password':
            raise errors.UnsupportedGrantTypeError()

        log.debug('Validating username %s and password %s.',
                  request.username, request.password)
        if not self.request_validator.validate_user(request.username,
                request.password, request.client, request):
            raise errors.InvalidGrantError('Invalid credentials given.')
        else:
            if not hasattr(request.client, 'client_id'):
                raise NotImplementedError(
                        'Validate user must set the '
                        'request.client.client_id attribute '
                        'in authenticate_client.')
        log.debug('Authorizing access to user %r.', request.user)

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        if request.client:
            request.client_id = request.client_id or request.client.client_id
        self.validate_scopes(request)


class ClientCredentialsGrant(GrantTypeBase):
    """`Client Credentials Grant`_

    The client can request an access token using only its client
    credentials (or other supported means of authentication) when the
    client is requesting access to the protected resources under its
    control, or those of another resource owner that have been previously
    arranged with the authorization server (the method of which is beyond
    the scope of this specification).

    The client credentials grant type MUST only be used by confidential
    clients.

        +---------+                                  +---------------+
        |         |                                  |               |
        |         |>--(A)- Client Authentication --->| Authorization |
        | Client  |                                  |     Server    |
        |         |<--(B)---- Access Token ---------<|               |
        |         |                                  |               |
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
            raise errors.InvalidRequestError('Request is missing grant type.')

        if not request.grant_type == 'client_credentials':
            raise errors.UnsupportedGrantTypeError()

        log.debug('Authenticating client, %r.', request)
        if not self.request_validator.authenticate_client(request):
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError()
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
        try:
            log.debug('Validating refresh token request, %r.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return None, {}, e.json, 400

        token = token_handler.create_token(request,
                refresh_token=self.issue_new_refresh_tokens)
        log.debug('Issuing new token to client id %r (%r), %r.',
                  request.client_id, request.client, token)
        return None, {}, json.dumps(token), 200

    def validate_token_request(self, request):
        # REQUIRED. Value MUST be set to "refresh_token".
        if request.grant_type != 'refresh_token':
            raise errors.UnsupportedGrantTypeError()

        if request.refresh_token is None:
            raise errors.InvalidRequestError(
                    description='Missing refresh token parameter.')

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
            raise errors.AccessDeniedError()

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
            raise errors.InvalidScopeError(state=request.state)

        # REQUIRED. The refresh token issued to the client.
        log.debug('Validating refresh token %s for client %r.',
                  request.refresh_token, request.client)
        if not self.request_validator.validate_refresh_token(
                request.refresh_token, request.client, request):
            log.debug('Invalid refresh token, %s, for client %r.',
                      request.refresh_token, request.client)
            raise errors.InvalidRequestError()
