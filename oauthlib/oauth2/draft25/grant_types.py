"""
oauthlib.oauth2.draft_25.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import unicode_literals
import json
from oauthlib.common import generate_token, add_params_to_uri
from oauthlib.oauth2.draft25 import errors
from oauthlib.uri_validate import is_absolute_uri


class RequestValidator(object):

    @property
    def response_types(self):
        return ('code', 'token')

    def validate_request(self, request, response_types=None):
        request.state = getattr(request, 'state', None)
        response_types = response_types or self.response_types or []

        if not request.client_id:
            raise errors.InvalidRequestError(state=request.state,
                    description='Missing client_id parameter.')

        if not request.response_type:
            raise errors.InvalidRequestError(state=request.state,
                    description='Missing response_type parameter.')

        if not self.validate_client(request.client_id):
            raise errors.UnauthorizedClientError(state=request.state)

        if not request.response_type in response_types:
            raise errors.UnsupportedResponseTypeError(state=request.state)

        self.validate_request_scopes(request)

        if getattr(request, 'redirect_uri', None):
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRequestError(state=request.state,
                        description='Non absolute redirect URI. See RFC3986')

            if not self.validate_redirect_uri(request.client_id, request.redirect_uri):
                raise errors.AccessDeniedError(state=request.state)
        else:
            request.redirect_uri = self.get_default_redirect_uri(request.client_id)
            if not request.redirect_uri:
                raise errors.AccessDeniedError(state=request.state)

        return True

    def validate_request_scopes(self, request):
        request.state = getattr(request, 'state', None)
        if request.scopes:
            if not self.validate_scopes(request.client_id, request.scopes):
                raise errors.InvalidScopeError(state=request.state)
        else:
            request.scopes = self.get_default_scopes(request.client_id)

    def validate_client(self, client, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_scopes(self, client, scopes):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_user(self, username, password, client=None):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_redirect_uri(self, client, redirect_uri):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_redirect_uri(self, client):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_scopes(self, client):
        raise NotImplementedError('Subclasses must implement this method.')


class GrantTypeBase(object):

    def create_authorization_response(self, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def create_token_response(self, request, token_handler):
        raise NotImplementedError('Subclasses must implement this method.')


class AuthorizationCodeGrant(GrantTypeBase):

    @property
    def scopes(self):
        return ('default',)

    @property
    def error_uri(self):
        return '/oauth_error'

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def create_authorization_code(self, request):
        """Generates an authorization grant represented as a dictionary."""
        grant = {'code': generate_token()}
        if hasattr(request, 'state') and request.state:
            grant['state'] = request.state
        return grant

    def save_authorization_code(self, client_id, grant):
        """Saves authorization codes for later use by the token endpoint."""
        raise NotImplementedError('Subclasses must implement this method.')

    def create_authorization_response(self, request, token_handler):
        try:
            self.request_validator.validate_request(request)

        except errors.OAuth2Error as e:
            request.redirect_uri = getattr(request, 'redirect_uri',
                    self.error_uri)
            return add_params_to_uri(request.redirect_uri, e.twotuples)

        grant = self.create_authorization_code(request)
        self.save_authorization_code(request.client_id, grant)
        return add_params_to_uri(request.redirect_uri, grant.items())

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
        except errors.OAuth2Error as e:
            return e.json
        return json.dumps(token_handler(request, refresh_token=True))

    def validate_token_request(self, request):

        if getattr(request, 'grant_type', '') != 'authorization_code':
            raise errors.UnsupportedGrantTypeError()

        if not getattr(request, 'code', None):
            raise errors.InvalidRequestError(
                    description='Missing code parameter.')

        # TODO: document diff client & client_id, former is authenticated
        # outside spec, i.e. http basic
        if (not hasattr(request, 'client') or
            not self.request_validator.validate_client(request.client, request.grant_type)):
            raise errors.UnauthorizedClientError()

        if not self.request_validator.validate_code(request.client, request.code):
            raise errors.InvalidGrantError()

    # TODO: validate scopes


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
            self.request_validator.validate_request(request)
        except errors.OAuth2Error as e:
            return add_params_to_uri(request.redirect_uri, e.twotuples,
                    fragment=True)
        token = token_handler(request, refresh_token=False)
        return add_params_to_uri(request.redirect_uri, token.items(),
                fragment=True), {}, None


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
                self.request_validator.authenticate_client(request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return None, {}, e.json
        return None, {}, json.dumps(token_handler(request, refresh_token=True))

    def validate_token_request(self, request):
        for param in ('grant_type', 'username', 'password'):
            if not getattr(request, param):
                raise errors.InvalidRequestError(
                        'Request is missing %s parameter.' % param)

        # This error should rarely (if ever) occur if requests are routed to
        # grant type handlers based on the grant_type parameter.
        if not request.grant_type == 'password':
            raise errors.UnsupportedGrantTypeError()

        # request.client is populated during client authentication
        client = request.client if getattr(request, 'client') else None
        if not self.request_validator.validate_user(request.username,
                request.password, client=client):
            raise errors.InvalidGrantError('Invalid credentials given.')

        self.request_validator.validate_request_scopes(request)


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
            self.request_validator.authenticate_client(request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return None, {}, e.json
        return None, {}, json.dumps(token_handler(request, refresh_token=True))

    def validate_token_request(self, request):
        if not getattr(request, 'grant_type'):
            raise errors.InvalidRequestError('Request is issing grant type.')

        if not request.grant_type == 'client_credentials':
            raise errors.UnsupportedGrantTypeError()

        self.request_validator.validate_request_scopes(request)
