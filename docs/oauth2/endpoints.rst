=================
OAuth 2 Endpoints
=================

Endpoints in OAuth 2 are targets with a specific responsibility and often
associated with a particular URL. Because of this the word endpoint might be
used interchangably from the endpoint url.

There main three responsibilities in an OAuth 2 flow is to authorize access to a
certain users resources to a client, to supply said client with a token
embodying this authorization and to verify that the token is valid when the
client attempts to access thee user resources on their behalf.

-------------
Authorization
-------------

Authorization can be either explicit or implicit. The former require the user to
actively authorize the client by being redirected to the authorization endpoint.
There he/she is usually presented by a form and asked to either accept or deny
access to certain scopes. These scopes can be thought of as Access Control Lists
that are tied to certain privileges and categories of resources, such as write
access to their status feed or read access to their profile. It is vital that
the implications of granting access to a certain scope is very clear in the
authorization form presented to the user. It is up to the provider to allow the
user agree to all, a few or none of the scopes. Being flexible here is a great
benefit to the user at the cost of added complexity in both the provider and
clients.

Implicit authorization happens when the authorization happens before the OAuth
flow, such as the user giving the client his/her password and username, or if
there is a very high level of trust between the user, client and provider and no
explicit authorization is necessary.

Examples of explicit authorization is the Authorization Code Grant and the
Implicit Grant.

Examples of implicit authorization is the Resource Owner Password Credentials
Grant and the Client Credentials Grant.

**Pre Authorization Request**
    OAuth is known for it's authorization page where the user accepts or denies
    access to a certain client and set of scopes. Before presenting the user
    with such a form you need to ensure the credentials the client supplied in
    the redirection to this page are valid::

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Validate request
        uri = 'https://example.com/authorize?client_id=foo&state=xyz
        headers, body, http_method = {}, '', 'GET'

        from oauthlib.oauth2 import FatalClientError
        from your_framework import redirect
        try:
            scopes, credentials = server.validate_authorization_request(
                uri, http_method, body, headers)
            # scopes will hold default scopes for client, i.e.
            ['https://example.com/userProfile', 'https://example.com/pictures']

            # credentials is a dictionary of
            {
                'client_id': 'foo',
                'redirect_uri': 'https://foo.com/welcome_back',
                'response_type': 'code',
                'state': 'randomstring',
            }
            # these credentials will be needed in the post authorization view and
            # should be persisted between. None of them are secret but take care
            # to ensure their integrety if embedding them in the form or cookies.
            from your_datastore import persist_credentials
            persist_credentials(credentials)

            # Present user with a nice form where client (id foo) request access to
            # his default scopes (omitted from request), after which you will
            # redirect to his default redirect uri (omitted from request).

        except FatalClientError as e:
            # this is your custom error page
            from your_views import authorization_error_page_uri
            # Use in_uri to embed error code and description in the redirect uri
            redirect(e.in_uri(authorization_error_page_uri))


**Post Authorization Request**
    Generally, this is where you handle the submitted form. Rather than using
    ``validate_authorization_request`` we use ``create_authorization_response``
    which in the case of Authorization Code Grant embed an authorization code in
    the client provided redirect uri::

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Validate request
        uri = 'https://example.com/post_authorize?client_id=foo
        headers, body, http_method = {}, '', 'GET'

        # Fetch the credentials saved in the pre authorization phase
        from your_datastore import fetch_credentials
        credentials = fetch_credentials()

        # Fetch authorized scopes from the request
        from your_framework import request
        scopes = request.POST.get('scopes')

        from oauthlib.oauth2 import FatalClientError, OAuth2Error
        from your_framework import redirect
        try:
            uri, headers, body, status = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            # uri = https://foo.com/welcome_back?code=somerandomstring&state=xyz
            # headers = {}, this might change to include suggested headers related
            # to cache best practices etc.
            # body = '', this might be set in future custom grant types
            # status = 302, suggested HTTP status code

            redirect(uri, headers=headers, status=status, body=body)

        except FatalClientError as e:
            # this is your custom error page
            from your_views import authorization_error_page_uri
            # Use in_uri to embed error code and description in the redirect uri
            redirect(e.in_uri(authorization_error_page_uri))

        except OAuth2Error as e:
            # Less grave errors will be reported back to client
            client_redirect_uri = credentials.get('redirect_uri')
            redirect(e.in_uri(client_redirect_uri))

.. autoclass:: oauthlib.oauth2.AuthorizationEndpoint
    :members:

--------------
Token creation
--------------

Token endpoints issue tokens to clients who have already been authorized access,
be it by explicit actions from the user or implicitely. The token response is
well defined and typically consist of an unguessable access token, the token
type, its expiration from now in seconds and depending on the scenario, a
refresh token to be used to fetch new access tokens without authorization.

One argument for OAuth 2 being more scalable than OAuth 1 is that tokens may
contain hidden information. A provider may embed information such as client
identifier, user identifier, expiration times, etc. in the token by encrypting
it. This trades a slight increase in work required to decrypt the token but
frees the necessary database lookups otherwise required, thus improving latency
substantially. OAuthlib currently does not provide a method for creating
crypto-tokens but may do in the future.

The standard token type, Bearer, does not require that the provider bind a
specific client to the token. Not binding clients to tokens allow for anonymized
tokens which unless you are certain you need them, are a bad idea.

**Token Request**
    A POST request used in most grant types but with a varied setup of
    credentials. If you wish to embed extra credentials in the request, i.e. for
    later use in validation or when creating the token, you can use the
    ``credentials`` argument in ``create_token_response``.

    All responses are in json format and the headers argument returned by
    ``create_token_response`` will contain a few suggested headers related to
    content type and caching::

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Validate request
        uri = 'https://example.com/token'
        http_method = 'POST'
        body = 'authorization_code=somerandomstring&'
               'grant_type=authorization_code&'
        # Clients authenticate through a method of your choosing, for example
        # using HTTP Basic Authentication
        headers = { 'Authorization': 'Basic ksjdhf923sf' }

        # Extra credentials you wish to include
        credentials = {'client_ip': '1.2.3.4'}

        uri, headers, body, status = server.create_token_response(
            uri, http_method, body, headers, credentials)

        # uri is not used by most grant types
        # headers will contain some suggested headers to add to your response
        {
            'Content-Type': 'application/json;charset=UTF-8',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        # body will contain the token in json format and expiration from now
        # in seconds.
        {
            'access_token': 'sldafh309sdf',
            'refresh_token': 'alsounguessablerandomstring',
            'expires_in': 3600,
            'scopes': [
                'https://example.com/userProfile',
                'https://example.com/pictures'
            ],
            'token_type': 'Bearer'
        }
        # body will contain an error code and possibly an error description if
        # the request failed, also in json format.
        {
            'error': 'invalid_grant_type',
            'description': 'athorizatoin_coed is not a valid grant type'
        }
        # status will be a suggested status code, 200 on ok, 400 on bad request
        # and 401 if client is trying to use an invalid authorization code,
        # fail to authenticate etc.

        from your_framework import http_response
        http_response(body, status=status, headers=headers)

.. autoclass:: oauthlib.oauth2.TokenEndpoint
    :members:

---------------------------
Authorizing resource access
---------------------------

Resource endpoints verify that the token presented is valid and granted access
to the scopes associated with the resource in question.

**Request Verfication**
    Each view may set certain scopes under which it is bound. Only requests
    that present an access token bound to the correct scopes may access the
    view. Access tokens are commonly embedded in the authorization header but
    may appear in the query or the body as well::

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Per view scopes
        required_scopes = ['https://example.com/userProfile']

        # Validate request
        uri = 'https://example.com/userProfile?access_token=sldafh309sdf'
        headers, body, http_method = {}, '', 'GET'

        valid, oauthlib_request = server.verify_request(
            uri, http_method, body, headers, required_scopes)

        # oauthlib_request has a few convenient attributes set such as
        # oauthlib_request.client = the client associated with the token
        # oauthlib_request.user = the user associated with the token
        # oauthlib_request.scopes = the scopes bound to this token

        if valid:
            # return the protected resource / view
        else:
            # return an http forbidden 403

.. autoclass:: oauthlib.oauth2.ResourceEndpoint
    :members:

