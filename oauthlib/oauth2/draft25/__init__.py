# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth2.draft_25
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 2.0 draft 25 requests.
"""
from oauthlib.common import Request
from oauthlib.oauth2.draft25 import errors
from .tokens import prepare_bearer_uri, prepare_bearer_headers
from .tokens import prepare_bearer_body, prepare_mac_header
from .tokens import BearerToken
from .parameters import prepare_grant_uri, prepare_token_request
from .parameters import parse_authorization_code_response
from .parameters import parse_implicit_response, parse_token_response
from .utils import params_from_uri


AUTH_HEADER = 'auth_header'
URI_QUERY = 'query'
BODY = 'body'


class Client(object):
    """Base OAuth2 client responsible for access tokens.

    While this class can be used to simply append tokens onto requests
    it is often more useful to use a client targeted at a specific workflow.
    """

    def __init__(self, client_id,
            default_token_placement=AUTH_HEADER,
            token_type='Bearer',
            access_token=None,
            refresh_token=None,
            mac_key=None,
            mac_algorithm=None,
            **kwargs):
        """Initialize a client with commonly used attributes."""

        self.client_id = client_id
        self.default_token_placement = default_token_placement
        self.token_type = token_type
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.mac_key = mac_key
        self.mac_algorithm = mac_algorithm

    @property
    def token_types(self):
        """Supported token types and their respective methods

        Additional tokens can be supported by extending this dictionary.

        The Bearer token spec is stable and safe to use.

        The MAC token spec is not yet stable and support for MAC tokens
        is experimental and currently matching version 00 of the spec.
        """
        return {
            'Bearer': self._add_bearer_token,
            'MAC': self._add_mac_token
        }

    def add_token(self, uri, http_method='GET', body=None, headers=None,
            token_placement=None, **kwargs):
        """Add token to the request uri, body or authorization header.

        The access token type provides the client with the information
        required to successfully utilize the access token to make a protected
        resource request (along with type-specific attributes).  The client
        MUST NOT use an access token if it does not understand the token
        type.

        For example, the "bearer" token type defined in
        [I-D.ietf-oauth-v2-bearer] is utilized by simply including the access
        token string in the request:

        GET /resource/1 HTTP/1.1
        Host: example.com
        Authorization: Bearer mF_9.B5f-4.1JqM

        while the "mac" token type defined in [I-D.ietf-oauth-v2-http-mac] is
        utilized by issuing a MAC key together with the access token which is
        used to sign certain components of the HTTP requests:

        GET /resource/1 HTTP/1.1
        Host: example.com
        Authorization: MAC id="h480djs93hd8",
                            nonce="274312:dj83hs9s",
                            mac="kDZvddkndxvhGRXZhvuDjEWhGeE="

        .. _`I-D.ietf-oauth-v2-bearer`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#ref-I-D.ietf-oauth-v2-bearer
        .. _`I-D.ietf-oauth-v2-http-mac`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#ref-I-D.ietf-oauth-v2-http-mac
        """
        token_placement = token_placement or self.default_token_placement

        if not self.token_type in self.token_types:
            raise ValueError("Unsupported token type: %s" % self.token_type)

        if not self.access_token:
            raise ValueError("Missing access token.")

        return self.token_types[self.token_type](uri, http_method, body,
                    headers, token_placement, **kwargs)

    def prepare_refresh_body(self, body='', refresh_token=None, scope=None, **kwargs):
        """Prepare an access token request, using a refresh token.

        If the authorization server issued a refresh token to the client, the
        client makes a refresh request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "refresh_token".
        refresh_token
                REQUIRED.  The refresh token issued to the client.
        scope
                OPTIONAL.  The scope of the access request as described by
                Section 3.3.  The requested scope MUST NOT include any scope
                not originally granted by the resource owner, and if omitted is
                treated as equal to the scope originally granted by the
                resource owner.
        """
        refresh_token = refresh_token or self.refresh_token
        return prepare_token_request('refresh_token', body=body, scope=scope,
                refresh_token=refresh_token, **kwargs)

    def _add_bearer_token(self, uri, http_method='GET', body=None,
            headers=None, token_placement=None):
        """Add a bearer token to the request uri, body or authorization header."""
        if token_placement == AUTH_HEADER:
            headers = prepare_bearer_headers(self.access_token, headers)

        elif token_placement == URI_QUERY:
            uri = prepare_bearer_uri(self.access_token, uri)

        elif token_placement == BODY:
            body = prepare_bearer_body(self.access_token, body)

        else:
            raise ValueError("Invalid token placement.")
        return uri, headers, body

    def _add_mac_token(self, uri, http_method='GET', body=None,
            headers=None, token_placement=AUTH_HEADER, ext=None, **kwargs):
        """Add a MAC token to the request authorization header.

        Warning: MAC token support is experimental as the spec is not yet stable.
        """
        headers = prepare_mac_header(self.access_token, uri, self.mac_key, http_method,
                        headers=headers, body=body, ext=ext,
                        hash_algorithm=self.mac_algorithm, **kwargs)
        return uri, headers, body

    def _populate_attributes(self, response):
        """Add commonly used values such as access_token to self."""

        if 'access_token' in response:
            self.access_token = response.get('access_token')

        if 'refresh_token' in response:
            self.refresh_token = response.get('refresh_token')

        if 'token_type' in response:
            self.token_type = response.get('token_type')

        if 'expires_in' in response:
            self.expires_in = response.get('expires_in')

        if 'code' in response:
            self.code = response.get('code')

        if 'mac_key' in response:
            self.mac_key = response.get('mac_key')

        if 'mac_algorithm' in response:
            self.mac_algorithm = response.get('mac_algorithm')

    def prepare_request_uri(self, *args, **kwargs):
        """Abstract method used to create request URIs."""
        raise NotImplementedError("Must be implemented by inheriting classes.")

    def prepare_request_body(self, *args, **kwargs):
        """Abstract method used to create request bodies."""
        raise NotImplementedError("Must be implemented by inheriting classes.")

    def parse_request_uri_response(self, *args, **kwargs):
        """Abstract method used to parse redirection responses."""

    def parse_request_body_response(self, *args, **kwargs):
        """Abstract method used to parse JSON responses."""


class WebApplicationClient(Client):
    """A client utilizing the authorization code grant workflow.

    A web application is a confidential client running on a web
    server.  Resource owners access the client via an HTML user
    interface rendered in a user-agent on the device used by the
    resource owner.  The client credentials as well as any access
    token issued to the client are stored on the web server and are
    not exposed to or accessible by the resource owner.

    The authorization code grant type is used to obtain both access
    tokens and refresh tokens and is optimized for confidential clients.
    As a redirection-based flow, the client must be capable of
    interacting with the resource owner's user-agent (typically a web
    browser) and capable of receiving incoming requests (via redirection)
    from the authorization server.
    """

    def __init__(self, client_id, code=None, **kwargs):
        super(WebApplicationClient, self).__init__(client_id, **kwargs)
        if code:
            self.code = code

    def prepare_request_uri(self, uri, redirect_uri=None, scope=None,
            state=None, **kwargs):
        """Prepare the authorization code request URI

        The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format as defined by
        [`W3C.REC-html401-19991224`_]:

        response_type
                REQUIRED.  Value MUST be set to "code".
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

        .. _`W3C.REC-html401-19991224`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#ref-W3C.REC-html401-19991224
        .. _`Section 2.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-2.2
        .. _`Section 3.1.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.1.2
        .. _`Section 3.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.3
        .. _`Section 10.12`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-10.12
        """
        return prepare_grant_uri(uri, self.client_id, 'code',
                redirect_uri=redirect_uri, scope=scope, state=state, **kwargs)

    def prepare_request_body(self, code=None, body='', redirect_uri=None, **kwargs):
        """Prepare the access token request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "authorization_code".
        code
                REQUIRED.  The authorization code received from the
                authorization server.
        redirect_uri
                REQUIRED, if the "redirect_uri" parameter was included in the
                authorization request as described in Section 4.1.1, and their
                values MUST be identical.

        .. _`Section 4.1.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1.1
        """
        code = code or self.code
        return prepare_token_request('authorization_code', code=code, body=body,
                                          redirect_uri=redirect_uri, **kwargs)

    def parse_request_uri_response(self, uri, state=None):
        """Parse the URI query for code and state.

        If the resource owner grants the access request, the authorization
        server issues an authorization code and delivers it to the client by
        adding the following parameters to the query component of the
        redirection URI using the "application/x-www-form-urlencoded" format:

        code
                REQUIRED.  The authorization code generated by the
                authorization server.  The authorization code MUST expire
                shortly after it is issued to mitigate the risk of leaks.  A
                maximum authorization code lifetime of 10 minutes is
                RECOMMENDED.  The client MUST NOT use the authorization code
                more than once.  If an authorization code is used more than
                once, the authorization server MUST deny the request and SHOULD
                revoke (when possible) all tokens previously issued based on
                that authorization code.  The authorization code is bound to
                the client identifier and redirection URI.
        state
                REQUIRED if the "state" parameter was present in the client
                authorization request.  The exact value received from the
                client.
        """
        response = parse_authorization_code_response(uri, state=state)
        self._populate_attributes(response)
        return response

    def parse_request_body_response(self, body, scope=None):
        """Parse the JSON response body.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request client
        authentication failed or is invalid, the authorization server returns
        an error response as described in `Section 5.2`_.

        .. `Section 5.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.1
        .. `Section 5.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.2
        """
        response = parse_token_response(body, scope=scope)
        self._populate_attributes(response)
        return response


class UserAgentClient(Client):
    """A public client utilizing the implicit code grant workflow.

    A user-agent-based application is a public client in which the
    client code is downloaded from a web server and executes within a
    user-agent (e.g. web browser) on the device used by the resource
    owner.  Protocol data and credentials are easily accessible (and
    often visible) to the resource owner.  Since such applications
    reside within the user-agent, they can make seamless use of the
    user-agent capabilities when requesting authorization.

    The implicit grant type is used to obtain access tokens (it does not
    support the issuance of refresh tokens) and is optimized for public
    clients known to operate a particular redirection URI.  These clients
    are typically implemented in a browser using a scripting language
    such as JavaScript.

    As a redirection-based flow, the client must be capable of
    interacting with the resource owner's user-agent (typically a web
    browser) and capable of receiving incoming requests (via redirection)
    from the authorization server.

    Unlike the authorization code grant type in which the client makes
    separate requests for authorization and access token, the client
    receives the access token as the result of the authorization request.

    The implicit grant type does not include client authentication, and
    relies on the presence of the resource owner and the registration of
    the redirection URI.  Because the access token is encoded into the
    redirection URI, it may be exposed to the resource owner and other
    applications residing on the same device.
    """

    def prepare_request_uri(self, uri, redirect_uri=None, scope=None,
            state=None, **kwargs):
        """Prepare the implicit grant request URI.

        The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format:

        response_type
                REQUIRED.  Value MUST be set to "token".
        client_id
                REQUIRED.  The client identifier as described in Section 2.2.
        redirect_uri
                OPTIONAL.  As described in Section 3.1.2.
        scope
                OPTIONAL.  The scope of the access request as described by
                Section 3.3.
        state
                RECOMMENDED.  An opaque value used by the client to maintain
                state between the request and callback.  The authorization
                server includes this value when redirecting the user-agent back
                to the client.  The parameter SHOULD be used for preventing
                cross-site request forgery as described in Section 10.12.
        """
        return prepare_grant_uri(uri, self.client_id, 'token',
                redirect_uri=redirect_uri, state=state, scope=scope, **kwargs)

    def parse_request_uri_response(self, uri, state=None, scope=None):
        """Parse the response URI fragment.

        If the resource owner grants the access request, the authorization
        server issues an access token and delivers it to the client by adding
        the following parameters to the fragment component of the redirection
        URI using the "application/x-www-form-urlencoded" format:

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
                OPTIONAL, if identical to the scope requested by the client,
                otherwise REQUIRED.  The scope of the access token as described
                by `Section 3.3`_.
        state
                REQUIRED if the "state" parameter was present in the client
                authorization request.  The exact value received from the
                client.

        .. _`Section 7.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-7.1
        .. _`Section 3.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.3
        """
        response = parse_implicit_response(uri, state=state, scope=scope)
        self._populate_attributes(response)
        return response


class ClientCredentialsClient(Client):
    """A public client utilizing the client credentials grant workflow.

    The client can request an access token using only its client
    credentials (or other supported means of authentication) when the
    client is requesting access to the protected resources under its
    control, or those of another resource owner which has been previously
    arranged with the authorization server (the method of which is beyond
    the scope of this specification).

    The client credentials grant type MUST only be used by confidential
    clients.

    Since the client authentication is used as the authorization grant,
    no additional authorization request is needed.
    """

    def prepare_request_body(self, body='', scope=None, **kwargs):
        """Add the client credentials to the request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "client_credentials".
        scope
                OPTIONAL.  The scope of the access request as described by
                `Section 3.3`_.

        .. _`Section 3.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.3
        """
        return prepare_token_request('client_credentials', body=body,
                                     scope=scope, **kwargs)

    def parse_request_body_response(self, body, scope=None):
        """Parse the JSON response body.

        If the access token request is valid and authorized, the
        authorization server issues an access token as described in
        `Section 5.1`_.  A refresh token SHOULD NOT be included.  If the request
        failed client authentication or is invalid, the authorization server
        returns an error response as described in `Section 5.2`_.

        .. `Section 5.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.1
        .. `Section 5.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.2
        """
        response = parse_token_response(body, scope=scope)
        self._populate_attributes(response)
        return response


class PasswordCredentialsClient(Client):
    """A public client using the resource owner password and username directly.

    The resource owner password credentials grant type is suitable in
    cases where the resource owner has a trust relationship with the
    client, such as the device operating system or a highly privileged
    application.  The authorization server should take special care when
    enabling this grant type, and only allow it when other flows are not
    viable.

    The grant type is suitable for clients capable of obtaining the
    resource owner's credentials (username and password, typically using
    an interactive form).  It is also used to migrate existing clients
    using direct authentication schemes such as HTTP Basic or Digest
    authentication to OAuth by converting the stored credentials to an
    access token.

    The method through which the client obtains the resource owner
    credentials is beyond the scope of this specification.  The client
    MUST discard the credentials once an access token has been obtained.
    """

    def __init__(self, client_id, username, password, **kwargs):
        super(PasswordCredentialsClient, self).__init__(client_id, **kwargs)
        self.username = username
        self.password = password

    def prepare_request_body(self, body='', scope=None, **kwargs):
        """Add the resource owner password and username to the request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "password".
        username
                REQUIRED.  The resource owner username.
        password
                REQUIRED.  The resource owner password.
        scope
                OPTIONAL.  The scope of the access request as described by
                `Section 3.3`_.

        .. _`Section 3.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-3.3
        """
        return prepare_token_request('password', body=body, username=self.username,
                password=self.password, scope=scope, **kwargs)

    def parse_request_body_response(self, body, scope=None):
        """Parse the JSON response body.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request failed client
        authentication or is invalid, the authorization server returns an
        error response as described in `Section 5.2`_.

        .. `Section 5.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.1
        .. `Section 5.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-5.2
        """
        response = parse_token_response(body, scope=scope)
        self._populate_attributes(response)
        return response


class AuthorizationEndpoint(object):
    """Authorization endpoint - used by the client to obtain authorization
    from the resource owner via user-agent redirection.

    The authorization endpoint is used to interact with the resource
    owner and obtain an authorization grant.  The authorization server
    MUST first verify the identity of the resource owner.  The way in
    which the authorization server authenticates the resource owner (e.g.
    username and password login, session cookies) is beyond the scope of
    this specification.

    The endpoint URI MAY include an "application/x-www-form-urlencoded"
    formatted (per Appendix B) query component ([RFC3986] section 3.4),
    which MUST be retained when adding additional query parameters.  The
    endpoint URI MUST NOT include a fragment component.

    Since requests to the authorization endpoint result in user
    authentication and the transmission of clear-text credentials (in the
    HTTP response), the authorization server MUST require the use of TLS
    as described in Section 1.6 when sending requests to the
    authorization endpoint.

    The authorization server MUST support the use of the HTTP "GET"
    method [RFC2616] for the authorization endpoint, and MAY support the
    use of the "POST" method as well.

    Parameters sent without a value MUST be treated as if they were
    omitted from the request.  The authorization server MUST ignore
    unrecognized request parameters.  Request and response parameters
    MUST NOT be included more than once.
    """

    def __init__(self, default_token=None, response_types=None):
        self._response_types = response_types or {}
        self._default_token = default_token or BearerToken()

    @property
    def response_types(self):
        return self._response_types

    @property
    def default_token(self):
        return self._default_token

    def create_authorization_response(self, uri, http_method='GET', body=None,
            headers=None):
        """Extract response_type and route to the designated handler."""
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        query_params = params_from_uri(self.request.uri)
        body_params = self.request.decoded_body

        # Prioritize response_type defined as query param over those in body.
        # Chosen because the two core grant types utilizing the response type
        # parameter both supply it in the uri. However it is not specified
        # explicitely in RFC 6748.
        if 'response_type' in query_params:
            request.response_type = query_params.get('response_type')
        elif 'response_type' in body_params:
            request.response_type = body_params.get('response_type')
        else:
            raise errors.InvalidRequestError(
                description='The response_type parameter is missing.')

        if not request.response_type in self.response_types:
            raise errors.UnsupportedResponseTypeError(
                description='Invalid response type')

        return self.response_types.get(
                request.response_type).create_authorization_response(
                        request, self.default_token)


class TokenEndpoint(object):

    def __init__(self, default_token=None, grant_types=None):
        self._grant_types = grant_types or {}
        self._default_token = default_token or BearerToken()

    @property
    def grant_types(self):
        return self._grant_types

    @property
    def default_token(self):
        return self._default_token

    def create_token_response(self, uri, http_method='GET', body=None, headers=None):
        """Extract grant_type and route to the designated handler."""
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        query_params = params_from_uri(self.request.uri)
        body_params = self.request.decoded_body

        # Prioritize grant_type defined as body param over those in uri.
        # Chosen because all three core grant types supply this parameter
        # in the body. However it is not specified explicitely in RFC 6748.
        if 'grant_type' in body_params:
            request.grant_type = query_params.get('grant_type')
        elif 'grant_type' in query_params:
            request.grant_type = body_params.get('grant_type')
        else:
            raise errors.InvalidRequestError(
                description='The grant_type parameter is missing.')

        if not request.grant_type in self.grant_types:
            raise errors.UnsupportedGrantTypeError(
                description='Invalid response type')

        return self.grant_types.get(
                request.grant_type).create_token_response(
                        request, self.default_token)


class ResourceEndpoint(object):

    def __init__(self, tokens=None):
        self._tokens = tokens or {'Bearer': BearerToken()}

    @property
    def tokens(self):
        return self._tokens

    def verify_request(self, uri, http_method='GET', body=None, headers=None):
        """Validate client, code etc, return body + headers"""
        request = Request(uri, http_method, body, headers)
        request.token_type = self.find_token_type(request)

        # TODO(ib-lundgren): How to return errors is not strictly defined and
        # should allow for customization.
        if not request.token_type:
            raise ValueError('Could not determine the token type.')

        if not request.token_type in self.tokens:
            raise ValueError('Unsupported token type.')

        return self.tokens.get(request.token_type).validate_request(request)

    def find_token_type(self, request):
        """Token type identification.

        RFC 6749 does not provide a method for easily differentiating between
        different token types during protected resource access. We estimate
        the most likely token type (if any) by asking each known token type
        to give an estimation based on the request.
        """
        estimates = sorted((t.estimate_type(request) for t in self.tokens))
        return estimates[0] if len(estimates) else None


class Server(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint):
    pass
