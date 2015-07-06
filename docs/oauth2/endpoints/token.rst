==============
Token creation
==============

Token endpoints issue tokens to clients who have already been authorized access,
be it by explicit actions from the user or implicitly. The token response is
well defined and typically consists of an unguessable access token, the token
type, its expiration from now in seconds, and depending on the scenario, a
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
    content type and caching.

    .. code-block:: python

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Validate request
        uri = 'https://example.com/token'
        http_method = 'POST'
        body = 'code=somerandomstring&'
               'grant_type=authorization_code&'
        # Clients authenticate through a method of your choosing, for example
        # using HTTP Basic Authentication
        headers = { 'Authorization': 'Basic ksjdhf923sf' }

        # Extra credentials you wish to include
        credentials = {'client_ip': '1.2.3.4'}

        headers, body, status = server.create_token_response(
            uri, http_method, body, headers, credentials)

        # headers will contain some suggested headers to add to your response
        {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        # body will contain the token in json format and expiration from now
        # in seconds.
        {
            'access_token': 'sldafh309sdf',
            'refresh_token': 'alsounguessablerandomstring',
            'expires_in': 3600,
            'scope': 'https://example.com/userProfile https://example.com/pictures',
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
