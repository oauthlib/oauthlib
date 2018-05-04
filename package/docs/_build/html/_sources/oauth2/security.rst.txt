========
Security
========

OAuth 2 is much simpler to implement for clients than OAuth 1 as
cryptographic signing is no longer necessary. Instead a strict
requirement on the use of TLS for all connections have been
introduced.

.. warning::

    OAuthLib will raise errors if you attempt to interact with a
    non HTTPS endpoint during authorization.
    However OAuthLib offers no such protection during token requests
    as the URI is not provided, only the request body.

Note that while OAuth 2 is simpler it does subtly transfer a few important
responsibilities from the provider to the client. Most notably that the client
must ensure that all tokens are kept secret at all times. Access to protected
resources using Bearer tokens provides no authenticity of clients which means
that a malicious party able to obtain your tokens can use them without the
provider being able to know the difference. This is unlike OAuth 1 where a
lost token could not be utilized without the client secret and the token
bound secret, since they are required for the signing of each request.


Environment Variables
---------------------
It is possible to customize some of the security settings in OAuthLib using
environment variables. You can use this to bypass some of OAuthLib's security
checks in order to run automated tests. *Never* bypass these checks in production.

.. envvar:: OAUTHLIB_INSECURE_TRANSPORT

    Normally, OAuthLib will raise an
    :class:`~oauthlib.oauth2.rfc6749.errors.InsecureTransportError`
    if you attempt to use OAuth2 over HTTP, rather than HTTPS. Setting this
    environment variable will prevent this error from being raised.
    This is mostly useful for local testing, or automated tests.
    *Never* set this variable in production.

.. envvar:: OAUTHLIB_STRICT_TOKEN_TYPE

    When parsing an OAuth2 token response, OAuthLib normally ignores the
    ``token_type`` parameter. Setting this variable will cause OAuthLib to
    specifically check for this parameter in the response, and raise an
    :class:`~oauthlib.oauth2.rfc6749.errors.MissingTokenTypeError` if the
    parameter is missing.
