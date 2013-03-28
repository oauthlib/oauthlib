# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth2.draft_25
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 2.0 draft 25 requests.
"""
import datetime
import functools
import logging

from oauthlib.common import Request
from oauthlib.oauth2.draft25 import tokens, grant_types
from .errors import TokenExpiredError, InsecureTransportError
from .errors import TemporarilyUnavailableError, ServerError
from .errors import FatalClientError, OAuth2Error
from .parameters import prepare_grant_uri, prepare_token_request
from .parameters import parse_authorization_code_response
from .parameters import parse_implicit_response, parse_token_response


AUTH_HEADER = 'auth_header'
URI_QUERY = 'query'
BODY = 'body'

log = logging.getLogger('oauthlib')

# Add a NullHandler to prevent warnings for users who don't wish
# to configure logging.
try:
    log.addHandler(logging.NullHandler())
# NullHandler gracefully backported to 2.6
except AttributeError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass
    log.addHandler(NullHandler())


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
            token=None,
            **kwargs):
        """Initialize a client with commonly used attributes."""

        self.client_id = client_id
        self.default_token_placement = default_token_placement
        self.token_type = token_type
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.mac_key = mac_key
        self.mac_algorithm = mac_algorithm
        self.token = token or {}
        self._expires_at = None
        self._populate_attributes(self.token)

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
        if not uri.lower().startswith('https://'):
            raise InsecureTransportError()

        token_placement = token_placement or self.default_token_placement

        case_insensitive_token_types = dict((k.lower(), v) for k, v in self.token_types.items())
        if not self.token_type.lower() in case_insensitive_token_types:
            raise ValueError("Unsupported token type: %s" % self.token_type)

        if not self.access_token:
            raise ValueError("Missing access token.")

        if self._expires_at and self._expires_at < datetime.datetime.now():
            raise TokenExpiredError()

        return case_insensitive_token_types[self.token_type.lower()](uri, http_method, body,
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
            headers = tokens.prepare_bearer_headers(self.access_token, headers)

        elif token_placement == URI_QUERY:
            uri = tokens.prepare_bearer_uri(self.access_token, uri)

        elif token_placement == BODY:
            body = tokens.prepare_bearer_body(self.access_token, body)

        else:
            raise ValueError("Invalid token placement.")
        return uri, headers, body

    def _add_mac_token(self, uri, http_method='GET', body=None,
            headers=None, token_placement=AUTH_HEADER, ext=None, **kwargs):
        """Add a MAC token to the request authorization header.

        Warning: MAC token support is experimental as the spec is not yet stable.
        """
        headers = tokens.prepare_mac_header(self.access_token, uri,
                self.mac_key, http_method, headers=headers, body=body, ext=ext,
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
            self._expires_at = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(self.expires_in))

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
        self.code = code

    def prepare_request_uri(self, uri, redirect_uri=None, scope=None,
            state=None, **kwargs):
        """Prepare the authorization code request URI

        The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format, per `Appendix B`_:

        :param redirect_uri:  OPTIONAL. The redirect URI must be an absolute URI
                              and it should have been registerd with the OAuth
                              provider prior to use. As described in `Section 3.1.2`_.

        :param scope:  OPTIONAL. The scope of the access request as described by
                       Section 3.3`_. These may be any string but are commonly
                       URIs or various categories such as ``videos`` or ``documents``.

        :param state:   RECOMMENDED.  An opaque value used by the client to maintain
                        state between the request and callback.  The authorization
                        server includes this value when redirecting the user-agent back
                        to the client.  The parameter SHOULD be used for preventing
                        cross-site request forgery as described in `Section 10.12`_.

        :param kwargs:  Extra arguments to include in the request URI.

        In addition to supplied parameters, OAuthLib will append the ``client_id``
        that was provided in the constructor as well as the mandatory ``response_type``
        argument, set to ``code``::

            >>> from oauthlib.oauth2 import WebApplicationClient
            >>> client = WebApplicationClient('your_id')
            >>> client.prepare_request_uri('https://example.com')
            'https://example.com?client_id=your_id&response_type=code'
            >>> client.prepare_request_uri('https://example.com', redirect_uri='https://a.b/callback')
            'https://example.com?client_id=your_id&response_type=code&redirect_uri=https%3A%2F%2Fa.b%2Fcallback'
            >>> client.prepare_request_uri('https://example.com', scope=['profile', 'pictures'])
            'https://example.com?client_id=your_id&response_type=code&scope=profile+pictures'
            >>> client.prepare_request_uri('https://example.com', foo='bar')
            'https://example.com?client_id=your_id&response_type=code&foo=bar'

        .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
        .. _`Section 2.2`: http://tools.ietf.org/html/rfc6749#section-2.2
        .. _`Section 3.1.2`: http://tools.ietf.org/html/rfc6749#section-3.1.2
        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 10.12`: http://tools.ietf.org/html/rfc6749#section-10.12
        """
        return prepare_grant_uri(uri, self.client_id, 'code',
                redirect_uri=redirect_uri, scope=scope, state=state, **kwargs)

    def prepare_request_body(self, client_id=None, code=None, body='',
            redirect_uri=None, **kwargs):
        """Prepare the access token request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        :param client_id:   REQUIRED, if the client is not authenticating with the
                            authorization server as described in `Section 3.2.1`_.

        :param code:    REQUIRED. The authorization code received from the
                        authorization server.

        :param redirect_uri:    REQUIRED, if the "redirect_uri" parameter was included in the
                                authorization request as described in `Section 4.1.1`_, and their
                                values MUST be identical.

        :param kwargs: Extra parameters to include in the token request.

        In addition OAuthLib will add the ``grant_type`` parameter set to
        ``authorization_code``.

        If the client type is confidential or the client was issued client
        credentials (or assigned other authentication requirements), the
        client MUST authenticate with the authorization server as described
        in `Section 3.2.1`_::

            >>> from oauthlib.oauth2 import WebApplicationClient
            >>> client = WebApplicationClient('your_id')
            >>> client.prepare_request_body(code='sh35ksdf09sf')
            'grant_type=authorization_code&code=sh35ksdf09sf'
            >>> client.prepare_request_body(code='sh35ksdf09sf', foo='bar')
            'grant_type=authorization_code&code=sh35ksdf09sf&foo=bar'

        .. _`Section 4.1.1`: http://tools.ietf.org/html/rfc6749#section-4.1.1
        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        code = code or self.code
        return prepare_token_request('authorization_code', code=code, body=body,
                client_id=self.client_id, redirect_uri=redirect_uri, **kwargs)

    def parse_request_uri_response(self, uri, state=None):
        """Parse the URI query for code and state.

        If the resource owner grants the access request, the authorization
        server issues an authorization code and delivers it to the client by
        adding the following parameters to the query component of the
        redirection URI using the "application/x-www-form-urlencoded" format:

        :param uri: The callback URI that resulted from the user being redirected
                    back from the provider to you, the client.
        :param state: The state provided in the authorization request.

        **code**
            The authorization code generated by the authorization server.
            The authorization code MUST expire shortly after it is issued
            to mitigate the risk of leaks. A maximum authorization code
            lifetime of 10 minutes is RECOMMENDED. The client MUST NOT
            use the authorization code more than once. If an authorization
            code is used more than once, the authorization server MUST deny
            the request and SHOULD revoke (when possible) all tokens
            previously issued based on that authorization code.
            The authorization code is bound to the client identifier and
            redirection URI.

        **state**
                If the "state" parameter was present in the authorization request.

        This method is mainly intended to enforce strict state checking with
        the added benefit of easily extracting parameters from the URI::

            >>> from oauthlib.oauth2 import WebApplicationClient
            >>> client = WebApplicationClient('your_id')
            >>> uri = 'https://example.com/callback?code=sdfkjh345&state=sfetw45'
            >>> client.parse_request_uri_response(uri, state='sfetw45')
            {'state': 'sfetw45', 'code': 'sdfkjh345'}
            >>> client.parse_request_uri_response(uri, state='other')
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 357, in parse_request_uri_response
                    back from the provider to you, the client.
                File "oauthlib/oauth2/draft25/parameters.py", line 153, in parse_authorization_code_response
                    raise MismatchingStateError()
            oauthlib.oauth2.draft25.errors.MismatchingStateError
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

        :param body: The response body from the token request.
        :param scope: Scopes originally requested.
        :return: Dictionary of token parameters.
        :raises: Warning if scope has changed. OAuth2Error if response is invalid.

        These response are json encoded and could easily be parsed without
        the assistance of OAuthLib. However, there are a few subtle issues
        to be aware of regarding the response which are helpfully addressed
        through the raising of various errors.

        A successful response should always contain

        **access_token**
                The access token issued by the authorization server. Often
                a random string.

        **token_type**
            The type of the token issued as described in `Section 7.1`_.
            Commonly ``Bearer``.

        While it is not mandated it is recommended that the provider include

        **expires_in**
            The lifetime in seconds of the access token.  For
            example, the value "3600" denotes that the access token will
            expire in one hour from the time the response was generated.
            If omitted, the authorization server SHOULD provide the
            expiration time via other means or document the default value.

        **scope**
            Providers may supply this in all responses but are required to only
            if it has changed since the authorization request.

        A normal response might look like::

            >>> json.loads(response_body)
            {
                    'access_token': 'sdfkjh345',
                    'token_type': 'Bearer',
                    'expires_in': '3600',
                    'refresh_token': 'x345dgasd',
                    'scope': 'hello world',
            }
            >>> from oauthlib.oauth2 import WebApplicationClient
            >>> client = WebApplicationClient('your_id')
            >>> client.parse_request_body_response(response_body)
            {
                    'access_token': 'sdfkjh345',
                    'token_type': 'Bearer',
                    'expires_in': '3600',
                    'refresh_token': 'x345dgasd',
                    'scope': ['hello', 'world'],    # note the list
            }

        If there was a scope change you will be notified with a warning::

            >>> client.parse_request_body_response(response_body, scope=['images'])
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                    .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
                File "oauthlib/oauth2/draft25/parameters.py", line 263, in parse_token_response
                    validate_token_parameters(params, scope)
                File "oauthlib/oauth2/draft25/parameters.py", line 285, in validate_token_parameters
                    raise Warning("Scope has changed to %s." % new_scope)
            Warning: Scope has changed to [u'hello', u'world'].

        If there was an error on the providers side you will be notified with
        an error. For example, if there was no ``token_type`` provided::

            >>> client.parse_request_body_response(response_body)
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                    File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                File "oauthlib/oauth2/draft25/parameters.py", line 263, in parse_token_response
                    validate_token_parameters(params, scope)
                File "oauthlib/oauth2/draft25/parameters.py", line 276, in validate_token_parameters
                    raise MissingTokenTypeError()
            oauthlib.oauth2.draft25.errors.MissingTokenTypeError

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        .. _`Section 7.1`: http://tools.ietf.org/html/rfc6749#section-7.1
        """
        self.token = parse_token_response(body, scope=scope)
        self._populate_attributes(self.token)
        return self.token


class MobileApplicationClient(Client):
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
        using the "application/x-www-form-urlencoded" format, per `Appendix B`_:

        :param redirect_uri:  OPTIONAL. The redirect URI must be an absolute URI
                              and it should have been registerd with the OAuth
                              provider prior to use. As described in `Section 3.1.2`_.

        :param scope:  OPTIONAL. The scope of the access request as described by
                       Section 3.3`_. These may be any string but are commonly
                       URIs or various categories such as ``videos`` or ``documents``.

        :param state:   RECOMMENDED.  An opaque value used by the client to maintain
                        state between the request and callback.  The authorization
                        server includes this value when redirecting the user-agent back
                        to the client.  The parameter SHOULD be used for preventing
                        cross-site request forgery as described in `Section 10.12`_.

        :param kwargs:  Extra arguments to include in the request URI.

        In addition to supplied parameters, OAuthLib will append the ``client_id``
        that was provided in the constructor as well as the mandatory ``response_type``
        argument, set to ``token``::

            >>> from oauthlib.oauth2 import MobileApplicationClient
            >>> client = MobileApplicationClient('your_id')
            >>> client.prepare_request_uri('https://example.com')
            'https://example.com?client_id=your_id&response_type=token'
            >>> client.prepare_request_uri('https://example.com', redirect_uri='https://a.b/callback')
            'https://example.com?client_id=your_id&response_type=token&redirect_uri=https%3A%2F%2Fa.b%2Fcallback'
            >>> client.prepare_request_uri('https://example.com', scope=['profile', 'pictures'])
            'https://example.com?client_id=your_id&response_type=token&scope=profile+pictures'
            >>> client.prepare_request_uri('https://example.com', foo='bar')
            'https://example.com?client_id=your_id&response_type=token&foo=bar'

        .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
        .. _`Section 2.2`: http://tools.ietf.org/html/rfc6749#section-2.2
        .. _`Section 3.1.2`: http://tools.ietf.org/html/rfc6749#section-3.1.2
        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 10.12`: http://tools.ietf.org/html/rfc6749#section-10.12
        """
        return prepare_grant_uri(uri, self.client_id, 'token',
                redirect_uri=redirect_uri, state=state, scope=scope, **kwargs)

    def parse_request_uri_response(self, uri, state=None, scope=None):
        """Parse the response URI fragment.

        If the resource owner grants the access request, the authorization
        server issues an access token and delivers it to the client by adding
        the following parameters to the fragment component of the redirection
        URI using the "application/x-www-form-urlencoded" format:

        :param uri: The callback URI that resulted from the user being redirected
                    back from the provider to you, the client.
        :param state: The state provided in the authorization request.
        :param scope: The scopes provided in the authorization request.
        :return: Dictionary of token parameters.
        :raises: Warning if scope has changed. OAuth2Error if response is invalid.

        A successful response should always contain

        **access_token**
                The access token issued by the authorization server. Often
                a random string.

        **token_type**
            The type of the token issued as described in `Section 7.1`_.
            Commonly ``Bearer``.

        **state**
            If you provided the state parameter in the authorization phase, then
            the provider is required to include that exact state value in the
            response.

        While it is not mandated it is recommended that the provider include

        **expires_in**
            The lifetime in seconds of the access token.  For
            example, the value "3600" denotes that the access token will
            expire in one hour from the time the response was generated.
            If omitted, the authorization server SHOULD provide the
            expiration time via other means or document the default value.

        **scope**
            Providers may supply this in all responses but are required to only
            if it has changed since the authorization request.

        A few example responses can be seen below::

            >>> response_uri = 'https://example.com/callback#access_token=sdlfkj452&state=ss345asyht&token_type=Bearer&scope=hello+world'
            >>> from oauthlib.oauth2 import MobileApplicationClient
            >>> client = MobileApplicationClient('your_id')
            >>> client.parse_request_uri_response(response_uri)
            {
                'access_token': 'sdlfkj452',
                'token_type': 'Bearer',
                'state': 'ss345asyht',
                'scope': [u'hello', u'world']
            }
            >>> client.parse_request_uri_response(response_uri, state='other')
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 598, in parse_request_uri_response
                    **scope**
                File "oauthlib/oauth2/draft25/parameters.py", line 197, in parse_implicit_response
                    raise ValueError("Mismatching or missing state in params.")
            ValueError: Mismatching or missing state in params.
            >>> client.parse_request_uri_response(response_uri, scope=['other'])
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 598, in parse_request_uri_response
                    **scope**
                File "oauthlib/oauth2/draft25/parameters.py", line 199, in parse_implicit_response
                    validate_token_parameters(params, scope)
                File "oauthlib/oauth2/draft25/parameters.py", line 285, in validate_token_parameters
                    raise Warning("Scope has changed to %s." % new_scope)
            Warning: Scope has changed to [u'hello', u'world'].

        .. _`Section 7.1`: http://tools.ietf.org/html/rfc6749#section-7.1
        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        """
        self.token = parse_implicit_response(uri, state=state, scope=scope)
        self._populate_attributes(self.token)
        return self.token


class BackendApplicationClient(Client):
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
        format per `Appendix B`_ in the HTTP request entity-body:

        :param scope:   The scope of the access request as described by
                        `Section 3.3`_.
        :param kwargs:  Extra credentials to include in the token request.

        The client MUST authenticate with the authorization server as
        described in `Section 3.2.1`_.

        The prepared body will include all provided credentials as well as
        the ``grant_type`` parameter set to ``client_credentials``::

            >>> from oauthlib.oauth2 import BackendApplicationClient
            >>> client = BackendApplicationClient('your_id')
            >>> client.prepare_request_body(scope=['hello', 'world'])
            'grant_type=client_credentials&scope=hello+world'

        .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
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

        :param body: The response body from the token request.
        :param scope: Scopes originally requested.
        :return: Dictionary of token parameters.
        :raises: Warning if scope has changed. OAuth2Error if response is invalid.

        These response are json encoded and could easily be parsed without
        the assistance of OAuthLib. However, there are a few subtle issues
        to be aware of regarding the response which are helpfully addressed
        through the raising of various errors.

        A successful response should always contain

        **access_token**
                The access token issued by the authorization server. Often
                a random string.

        **token_type**
            The type of the token issued as described in `Section 7.1`_.
            Commonly ``Bearer``.

        While it is not mandated it is recommended that the provider include

        **expires_in**
            The lifetime in seconds of the access token.  For
            example, the value "3600" denotes that the access token will
            expire in one hour from the time the response was generated.
            If omitted, the authorization server SHOULD provide the
            expiration time via other means or document the default value.

        **scope**
            Providers may supply this in all responses but are required to only
            if it has changed since the authorization request.

        A normal response might look like::

            >>> json.loads(response_body)
            {
                    'access_token': 'sdfkjh345',
                    'token_type': 'Bearer',
                    'expires_in': '3600',
                    'refresh_token': 'x345dgasd',
                    'scope': 'hello world',
            }
            >>> from oauthlib.oauth2 import BackendApplicationClient
            >>> client = BackendApplicationClient('your_id')
            >>> client.parse_request_body_response(response_body)
            {
                    'access_token': 'sdfkjh345',
                    'token_type': 'Bearer',
                    'expires_in': '3600',
                    'refresh_token': 'x345dgasd',
                    'scope': ['hello', 'world'],    # note the list
            }

        If there was a scope change you will be notified with a warning::

            >>> client.parse_request_body_response(response_body, scope=['images'])
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                    .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
                File "oauthlib/oauth2/draft25/parameters.py", line 263, in parse_token_response
                    validate_token_parameters(params, scope)
                File "oauthlib/oauth2/draft25/parameters.py", line 285, in validate_token_parameters
                    raise Warning("Scope has changed to %s." % new_scope)
            Warning: Scope has changed to [u'hello', u'world'].

        If there was an error on the providers side you will be notified with
        an error. For example, if there was no ``token_type`` provided::

            >>> client.parse_request_body_response(response_body)
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                    File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                File "oauthlib/oauth2/draft25/parameters.py", line 263, in parse_token_response
                    validate_token_parameters(params, scope)
                File "oauthlib/oauth2/draft25/parameters.py", line 276, in validate_token_parameters
                    raise MissingTokenTypeError()
            oauthlib.oauth2.draft25.errors.MissingTokenTypeError

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        .. _`Section 7.1`: http://tools.ietf.org/html/rfc6749#section-7.1
        """
        self.token = parse_token_response(body, scope=scope)
        self._populate_attributes(self.token)
        return self.token


class LegacyApplicationClient(Client):
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

    def __init__(self, client_id, **kwargs):
        super(LegacyApplicationClient, self).__init__(client_id, **kwargs)

    def prepare_request_body(self, username, password, body='', scope=None, **kwargs):
        """Add the resource owner password and username to the request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format per `Appendix B`_ in the HTTP request entity-body:

        :param username:    The resource owner username.
        :param password:    The resource owner password.
        :param scope:   The scope of the access request as described by
                        `Section 3.3`_.
        :param kwargs:  Extra credentials to include in the token request.

        If the client type is confidential or the client was issued client
        credentials (or assigned other authentication requirements), the
        client MUST authenticate with the authorization server as described
        in `Section 3.2.1`_.

        The prepared body will include all provided credentials as well as
        the ``grant_type`` parameter set to ``password``::

            >>> from oauthlib.oauth2 import LegacyApplicationClient
            >>> client = LegacyApplicationClient('your_id')
            >>> client.prepare_request_body(username='foo', password='bar', scope=['hello', 'world'])
            'grant_type=password&username=foo&scope=hello+world&password=bar'

        .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        return prepare_token_request('password', body=body, username=username,
                password=password, scope=scope, **kwargs)

    def parse_request_body_response(self, body, scope=None):
        """Parse the JSON response body.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request failed client
        authentication or is invalid, the authorization server returns an
        error response as described in `Section 5.2`_.

        :param body: The response body from the token request.
        :param scope: Scopes originally requested.
        :return: Dictionary of token parameters.
        :raises: Warning if scope has changed. OAuth2Error if response is invalid.

        These response are json encoded and could easily be parsed without
        the assistance of OAuthLib. However, there are a few subtle issues
        to be aware of regarding the response which are helpfully addressed
        through the raising of various errors.

        A successful response should always contain

        **access_token**
                The access token issued by the authorization server. Often
                a random string.

        **token_type**
            The type of the token issued as described in `Section 7.1`_.
            Commonly ``Bearer``.

        While it is not mandated it is recommended that the provider include

        **expires_in**
            The lifetime in seconds of the access token.  For
            example, the value "3600" denotes that the access token will
            expire in one hour from the time the response was generated.
            If omitted, the authorization server SHOULD provide the
            expiration time via other means or document the default value.

        **scope**
            Providers may supply this in all responses but are required to only
            if it has changed since the authorization request.

        A normal response might look like::

            >>> json.loads(response_body)
            {
                    'access_token': 'sdfkjh345',
                    'token_type': 'Bearer',
                    'expires_in': '3600',
                    'refresh_token': 'x345dgasd',
                    'scope': 'hello world',
            }
            >>> from oauthlib.oauth2 import LegacyApplicationClient
            >>> client = LegacyApplicationClient('your_id')
            >>> client.parse_request_body_response(response_body)
            {
                    'access_token': 'sdfkjh345',
                    'token_type': 'Bearer',
                    'expires_in': '3600',
                    'refresh_token': 'x345dgasd',
                    'scope': ['hello', 'world'],    # note the list
            }

        If there was a scope change you will be notified with a warning::

            >>> client.parse_request_body_response(response_body, scope=['images'])
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                    .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
                File "oauthlib/oauth2/draft25/parameters.py", line 263, in parse_token_response
                    validate_token_parameters(params, scope)
                File "oauthlib/oauth2/draft25/parameters.py", line 285, in validate_token_parameters
                    raise Warning("Scope has changed to %s." % new_scope)
            Warning: Scope has changed to [u'hello', u'world'].

        If there was an error on the providers side you will be notified with
        an error. For example, if there was no ``token_type`` provided::

            >>> client.parse_request_body_response(response_body)
            Traceback (most recent call last):
                File "<stdin>", line 1, in <module>
                File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                    File "oauthlib/oauth2/draft25/__init__.py", line 421, in parse_request_body_response
                File "oauthlib/oauth2/draft25/parameters.py", line 263, in parse_token_response
                    validate_token_parameters(params, scope)
                File "oauthlib/oauth2/draft25/parameters.py", line 276, in validate_token_parameters
                    raise MissingTokenTypeError()
            oauthlib.oauth2.draft25.errors.MissingTokenTypeError

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        .. _`Section 7.1`: http://tools.ietf.org/html/rfc6749#section-7.1
        """
        self.token = parse_token_response(body, scope=scope)
        self._populate_attributes(self.token)
        return self.token


# TODO(ib-lundgren): Deprecate these names
class UserAgentClient(MobileApplicationClient):
    pass


class PasswordCredentialsClient(LegacyApplicationClient):
    pass


class ClientCredentialsClient(BackendApplicationClient):
    pass


class BaseEndpoint(object):
    def __init__(self):
        self._available = True
        self._catch_errors = False

    @property
    def available(self):
        return self._available

    @available.setter
    def available(self, available):
        self._available = available

    @property
    def catch_errors(self):
        return self._catch_errors

    @catch_errors.setter
    def catch_errors(self, catch_errors):
        self._catch_errors = catch_errors


def catch_errors_and_unavailability(f):
    @functools.wraps(f)
    def wrapper(endpoint, uri, *args, **kwargs):
        if not endpoint.available:
            e = TemporarilyUnavailableError()
            log.info('Endpoint unavailable, ignoring request %s.' % uri)
            return None, {}, e.json, 503

        if endpoint.catch_errors:
            try:
                return f(endpoint, uri, *args, **kwargs)
            except OAuth2Error:
                raise
            except FatalClientError:
                raise
            except Exception as e:
                error = ServerError()
                log.warning('Exception caught while processing request, %s.' % e)
                return None, {}, error.json, 500
        else:
            return f(endpoint, uri, *args, **kwargs)
    return wrapper


class AuthorizationEndpoint(BaseEndpoint):
    """Authorization endpoint - used by the client to obtain authorization
    from the resource owner via user-agent redirection.

    The authorization endpoint is used to interact with the resource
    owner and obtain an authorization grant.  The authorization server
    MUST first verify the identity of the resource owner.  The way in
    which the authorization server authenticates the resource owner (e.g.
    username and password login, session cookies) is beyond the scope of
    this specification.

    The endpoint URI MAY include an "application/x-www-form-urlencoded"
    formatted (per `Appendix B`_) query component,
    which MUST be retained when adding additional query parameters.  The
    endpoint URI MUST NOT include a fragment component::

        https://example.com/path?query=component             # OK
        https://example.com/path?query=component#fragment    # Not OK

    Since requests to the authorization endpoint result in user
    authentication and the transmission of clear-text credentials (in the
    HTTP response), the authorization server MUST require the use of TLS
    as described in Section 1.6 when sending requests to the
    authorization endpoint::

        # We will deny any request which URI schema is not with https

    The authorization server MUST support the use of the HTTP "GET"
    method [RFC2616] for the authorization endpoint, and MAY support the
    use of the "POST" method as well::

        # HTTP method is currently not enforced

    Parameters sent without a value MUST be treated as if they were
    omitted from the request.  The authorization server MUST ignore
    unrecognized request parameters.  Request and response parameters
    MUST NOT be included more than once::

        # Enforced through the design of oauthlib.common.Request

    .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
    """

    def __init__(self, default_response_type, default_token_type,
            response_types):
        BaseEndpoint.__init__(self)
        self._response_types = response_types
        self._default_response_type = default_response_type
        self._default_token_type = default_token_type

    @property
    def response_types(self):
        return self._response_types

    @property
    def default_response_type(self):
        return self._default_response_type

    @property
    def default_response_type_handler(self):
        return self.response_types.get(self.default_response_type)

    @property
    def default_token_type(self):
        return self._default_token_type

    @catch_errors_and_unavailability
    def create_authorization_response(self, uri, http_method='GET', body=None,
            headers=None, scopes=None, credentials=None):
        """Extract response_type and route to the designated handler."""
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        request.scopes = scopes
        # TODO: decide whether this should be a required argument
        request.user = None     # TODO: explain this in docs
        for k, v in (credentials or {}).items():
            setattr(request, k, v)
        response_type_handler = self.response_types.get(
                request.response_type, self.default_response_type_handler)
        log.debug('Dispatching response_type %s request to %r.',
                  request.response_type, response_type_handler)
        return response_type_handler.create_authorization_response(
                        request, self.default_token_type)

    @catch_errors_and_unavailability
    def validate_authorization_request(self, uri, http_method='GET', body=None,
            headers=None):
        """Extract response_type and route to the designated handler."""
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        request.scopes = None
        response_type_handler = self.response_types.get(
                request.response_type, self.default_response_type_handler)
        return response_type_handler.validate_authorization_request(request)


class TokenEndpoint(BaseEndpoint):
    """Token issuing endpoint.

    The token endpoint is used by the client to obtain an access token by
    presenting its authorization grant or refresh token.  The token
    endpoint is used with every authorization grant except for the
    implicit grant type (since an access token is issued directly).

    The means through which the client obtains the location of the token
    endpoint are beyond the scope of this specification, but the location
    is typically provided in the service documentation.

    The endpoint URI MAY include an "application/x-www-form-urlencoded"
    formatted (per `Appendix B`_) query component,
    which MUST be retained when adding additional query parameters.  The
    endpoint URI MUST NOT include a fragment component::

        https://example.com/path?query=component             # OK
        https://example.com/path?query=component#fragment    # Not OK

    Since requests to the authorization endpoint result in user
    Since requests to the token endpoint result in the transmission of
    clear-text credentials (in the HTTP request and response), the
    authorization server MUST require the use of TLS as described in
    Section 1.6 when sending requests to the token endpoint::

        # We will deny any request which URI schema is not with https

    The client MUST use the HTTP "POST" method when making access token
    requests::

        # HTTP method is currently not enforced

    Parameters sent without a value MUST be treated as if they were
    omitted from the request.  The authorization server MUST ignore
    unrecognized request parameters.  Request and response parameters
    MUST NOT be included more than once::

        # Delegated to each grant type.

    .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
    """

    def __init__(self, default_grant_type, default_token_type, grant_types):
        BaseEndpoint.__init__(self)
        self._grant_types = grant_types
        self._default_token_type = default_token_type
        self._default_grant_type = default_grant_type

    @property
    def grant_types(self):
        return self._grant_types

    @property
    def default_grant_type(self):
        return self._default_grant_type

    @property
    def default_grant_type_handler(self):
        return self.grant_types.get(self.default_grant_type)

    @property
    def default_token_type(self):
        return self._default_token_type

    @catch_errors_and_unavailability
    def create_token_response(self, uri, http_method='GET', body=None,
            headers=None, credentials=None):
        """Extract grant_type and route to the designated handler."""
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        request.extra_credentials = credentials
        grant_type_handler = self.grant_types.get(request.grant_type,
                self.default_grant_type_handler)
        log.debug('Dispatching grant_type %s request to %r.',
                  request.grant_type, grant_type_handler)
        return grant_type_handler.create_token_response(
                request, self.default_token_type)


class ResourceEndpoint(BaseEndpoint):
    """Authorizes access to protected resources.

    The client accesses protected resources by presenting the access
    token to the resource server.  The resource server MUST validate the
    access token and ensure that it has not expired and that its scope
    covers the requested resource.  The methods used by the resource
    server to validate the access token (as well as any error responses)
    are beyond the scope of this specification but generally involve an
    interaction or coordination between the resource server and the
    authorization server::

        # For most cases, returning a 403 should suffice.

    The method in which the client utilizes the access token to
    authenticate with the resource server depends on the type of access
    token issued by the authorization server.  Typically, it involves
    using the HTTP "Authorization" request header field [RFC2617] with an
    authentication scheme defined by the specification of the access
    token type used, such as [RFC6750]::

        # Access tokens may also be provided in query and body
        https://example.com/protected?access_token=kjfch2345sdf   # Query
        access_token=sdf23409df   # Body
    """
    def __init__(self, default_token, token_types):
        BaseEndpoint.__init__(self)
        self._tokens = token_types
        self._default_token = default_token

    @property
    def default_token(self):
        return self._default_token

    @property
    def default_token_type_handler(self):
        return self.tokens.get(self.default_token)

    @property
    def tokens(self):
        return self._tokens

    @catch_errors_and_unavailability
    def verify_request(self, uri, http_method='GET', body=None, headers=None,
            scopes=None):
        """Validate client, code etc, return body + headers"""
        request = Request(uri, http_method, body, headers)
        request.token_type = self.find_token_type(request)
        request.scopes = scopes
        token_type_handler = self.tokens.get(request.token_type,
                self.default_token_type_handler)
        log.debug('Dispatching token_type %s request to %r.',
                  request.token_type, token_type_handler)
        return token_type_handler.validate_request(request), request

    def find_token_type(self, request):
        """Token type identification.

        RFC 6749 does not provide a method for easily differentiating between
        different token types during protected resource access. We estimate
        the most likely token type (if any) by asking each known token type
        to give an estimation based on the request.
        """
        estimates = sorted(((t.estimate_type(request), n) for n, t in self.tokens.items()))
        return estimates[0][1] if len(estimates) else None


class Server(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring all four major grant types."""

    def __init__(self, request_validator, *args, **kwargs):
        auth_grant = grant_types.AuthorizationCodeGrant(request_validator)
        implicit_grant = grant_types.ImplicitGrant(request_validator)
        password_grant = grant_types.ResourceOwnerPasswordCredentialsGrant(request_validator)
        credentials_grant = grant_types.ClientCredentialsGrant(request_validator)
        refresh_grant = grant_types.RefreshTokenGrant(request_validator)
        bearer = tokens.BearerToken(request_validator)
        AuthorizationEndpoint.__init__(self, default_response_type='code',
                response_types={
                    'code': auth_grant,
                    'token': implicit_grant,
                },
                default_token_type=bearer)
        TokenEndpoint.__init__(self, default_grant_type='authorization_code',
                grant_types={
                    'authorization_code': auth_grant,
                    'password': password_grant,
                    'client_credentials': credentials_grant,
                    'refresh_token': refresh_grant,
                },
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})


class WebApplicationServer(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring Authorization code grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None, **kwargs):
        """Construct a new web application server.

        :param request_validator: An implementation of oauthlib.oauth2.RequestValidator.
        :param token_generator: A function to generate a token from a request.
        :param kwargs: Extra parameters to pass to authorization endpoint,
                       token endpoint and resource endpoint constructors.
        """
        auth_grant = grant_types.AuthorizationCodeGrant(request_validator)
        refresh_grant = grant_types.RefreshTokenGrant(request_validator)
        bearer = tokens.BearerToken(request_validator, token_generator)
        AuthorizationEndpoint.__init__(self, default_response_type='code',
                response_types={'code': auth_grant},
                default_token_type=bearer)
        TokenEndpoint.__init__(self, default_grant_type='authorization_code',
                grant_types={
                    'authorization_code': auth_grant,
                    'refresh_token': refresh_grant,
                },
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})


class MobileApplicationServer(AuthorizationEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring Implicit code grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None, **kwargs):
        implicit_grant = grant_types.ImplicitGrant(request_validator)
        bearer = tokens.BearerToken(request_validator, token_generator)
        AuthorizationEndpoint.__init__(self, default_response_type='token',
                response_types={'token': implicit_grant},
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})


class LegacyApplicationServer(TokenEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring Authorization code grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None, **kwargs):
        password_grant = grant_types.ResourceOwnerPasswordCredentialsGrant(request_validator)
        refresh_grant = grant_types.RefreshTokenGrant(request_validator)
        bearer = tokens.BearerToken(request_validator, token_generator)
        TokenEndpoint.__init__(self, default_grant_type='password',
                grant_types={
                    'password': password_grant,
                    'refresh_token': refresh_grant,
                },
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})


class BackendApplicationServer(TokenEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring Authorization code grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None, **kwargs):
        credentials_grant = grant_types.ClientCredentialsGrant(request_validator)
        bearer = tokens.BearerToken(request_validator, token_generator)
        TokenEndpoint.__init__(self, default_grant_type='client_credentials',
                grant_types={'client_credentials': credentials_grant},
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})
