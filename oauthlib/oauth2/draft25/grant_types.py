"""
oauthlib.oauth2.draft_25.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import unicode_literals
import json
from oauthlib import common
from oauthlib.oauth2.draft25 import errors, utils
from oauthlib.uri_validate import is_absolute_uri


class RequestValidator(object):

    def validate_client_id(self, client_id, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_client(self, client_id, grant_type, client, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_code(self, client_id, code, client, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_bearer_token(self, token):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_refresh_token(self, refresh_token, client, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def authenticate_client(self, request, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_scopes(self, client_id, scopes, client):
        raise NotImplementedError('Subclasses must implement this method.')

    def confirm_scopes(self, refresh_token, scopes):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_user(self, username, password, client=None):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_redirect_uri(self, client_id, redirect_uri):
        raise NotImplementedError('Subclasses must implement this method.')

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_redirect_uri(self, client_id):
        raise NotImplementedError('Subclasses must implement this method.')

    def save_request_token(self, token, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def save_authorization_code(self, client_id, code):
        raise NotImplementedError('Subclasses must implement this method.')


class GrantTypeBase(object):

    def create_authorization_response(self, request, token_handler):
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
        grant = {'code': common.generate_token()}
        if hasattr(request, 'state') and request.state:
            grant['state'] = request.state
        return grant

    def create_authorization_response(self, request, token_handler):
        try:
            self.validate_authorization_request(request)

        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.
        except errors.FatalClientError:
            raise

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the query component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B:
        # http://tools.ietf.org/html/rfc6749#appendix-B
        except errors.OAuth2Error as e:
            request.redirect_uri = request.redirect_uri or self.error_uri
            return common.add_params_to_uri(request.redirect_uri, e.twotuples), None, None, e.status_code

        grant = self.create_authorization_code(request)
        self.request_validator.save_authorization_code(request.client_id, grant)
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
        except errors.OAuth2Error as e:
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

        if not self.request_validator.validate_client_id(request.client_id):
            raise errors.InvalidClientIdError(state=request.state)

        # OPTIONAL. As described in Section 3.1.2.
        # http://tools.ietf.org/html/rfc6749#section-3.1.2
        if request.redirect_uri is not None:
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(state=request.state)

            if not self.request_validator.validate_redirect_uri(
                    request.client_id, request.redirect_uri):
                raise errors.MismatchingRedirectURIError(state=request.state)
        else:
            request.redirect_uri = self.request_validator.get_default_redirect_uri(request.client_id)
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

        # REQUIRED. Value MUST be set to "code".
        if request.response_type != 'code':
            raise errors.UnsupportedResponseTypeError(state=request.state)

        # OPTIONAL. The scope of the access request as described by Section 3.3
        # http://tools.ietf.org/html/rfc6749#section-3.3
        request.scopes = utils.scope_to_list(request.scope) or self.request_validator.get_default_scopes(request.client_id)
        if not self.request_validator.validate_scopes(request.client_id,
                request.scopes, request.client):
            raise errors.InvalidScopeError(state=request.state)

        return True, request.scopes, {
                'client_id': request.client_id,
                'redirect_uri': request.redirect_uri,
                'response_type': request.response_type
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
            raise errors.AccessDeniedError()

        # REQUIRED, if the client is not authenticating with the
        # authorization server as described in Section 3.2.1.
        # http://tools.ietf.org/html/rfc6749#section-3.2.1
        if not self.request_validator.validate_client(request.client_id,
                request.grant_type, request.client):
            raise errors.UnauthorizedClientError()

        # REQUIRED. The authorization code received from the
        # authorization server.
        if not self.request_validator.validate_code(request.client_id,
                request.code, request.client):
            raise errors.InvalidGrantError()

        # REQUIRED, if the "redirect_uri" parameter was included in the
        # authorization request as described in Section 4.1.1, and their
        # values MUST be identical.
        if not self.request_validator.confirm_redirect_uri(request.client_id,
                request.code, request.redirect_uri, request.client):
            raise errors.AccessDeniedError()

        return True

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
        except errors.FatalClientError:
            raise

        # If the resource owner denies the access request or if the request
        # fails for reasons other than a missing or invalid redirection URI,
        # the authorization server informs the client by adding the following
        # parameters to the fragment component of the redirection URI using the
        # "application/x-www-form-urlencoded" format, per Appendix B:
        # http://tools.ietf.org/html/rfc6749#appendix-B
        except errors.OAuth2Error as e:
            return common.add_params_to_uri(request.redirect_uri, e.twotuples,
                    fragment=True), {}, None, e.status_code

        token = token_handler.create_token(request, refresh_token=False)
        return common.add_params_to_uri(request.redirect_uri, token.items(),
                fragment=True), {}, None, 200


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

        if not self.request_validator.validate_client_id(request.client_id):
            raise errors.InvalidClientIdError(state=request.state)

        # OPTIONAL. As described in Section 3.1.2.
        # http://tools.ietf.org/html/rfc6749#section-3.1.2
        if request.redirect_uri is not None:
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
            request.redirect_uri = self.request_validator.get_default_redirect_uri(request.client_id)
            if not request.redirect_uri:
                raise errors.MissingRedirectURIError(state=request.state)

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

        # OPTIONAL. The scope of the access request as described by Section 3.3
        # http://tools.ietf.org/html/rfc6749#section-3.3
        if not self.request_validator.validate_scopes(request):
            raise errors.InvalidScopeError(state=request.state)


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
            return None, {}, e.json, e.status_code

        return None, {}, json.dumps(token_handler.create_token(request, refresh_token=True)), 200

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
            return None, {}, e.json, e.status_code

        return None, {}, json.dumps(token_handler.create_token(request, refresh_token=False)), 200

    def validate_token_request(self, request):
        if not getattr(request, 'grant_type'):
            raise errors.InvalidRequestError('Request is issing grant type.')

        if not request.grant_type == 'client_credentials':
            raise errors.UnsupportedGrantTypeError()

        self.request_validator.validate_request_scopes(request)


class RefreshTokenGrant(GrantTypeBase):
    """`Refresh token grant`_

    .. _`Refresh token grant`: http://tools.ietf.org/html/rfc6749#section-6
    """

    @property
    def scope(self):
        return ('default',)

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
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return None, {}, e.json, 400

        token = token_handler.create_token(request,
                refresh_token=self.issue_new_refresh_tokens)
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
        if not self.request_validator.authenticate_client(request):
            raise errors.AccessDeniedError()

        # OPTIONAL. The scope of the access request as described by
        # Section 3.3. The requested scope MUST NOT include any scope
        # not originally granted by the resource owner, and if omitted is
        # treated as equal to the scope originally granted by the
        # resource owner.
        if not self.request_validator.confirm_scopes(request.refresh_token,
                request.scopes):
            raise errors.InvalidScopeError(state=request.state)

        # REQUIRED. The refresh token issued to the client.
        if not self.request_validator.validate_refresh_token(
                request.refresh_token, request.client):
            raise errors.InvalidRequestError()
