=============
Using Clients
=============

OAuthLib supports all four core grant types defined in the OAuth 2 RFC and
will continue to add more as they are defined. For more information on how
to use them please browse the documentation for each client type below.

.. toctree::
    :maxdepth: 2

    baseclient
    webapplicationclient
    mobileapplicationclient
    legacyapplicationclient
    backendapplicationclient

**A few notes on security**
    OAuth 2 is much simpler to implement for clients than OAuth 1 as
    cryptographic signing is no longer necessary. Instead a strict
    requirement on the use of TLS for all connections have been
    introduced::

        # OAuthLib will raise errors if you attempt to interact with a
        # non HTTPS endpoint during authorization.
        # However OAuthLib offers no such protection during token requests
        # as the URI is not provided, only the request body.

    Note that while OAuth 2 is simpler it does subtly transfer a few important
    responsibilities from the provider to the client. Most notably that the client
    must ensure that all tokens are kept secret at all times. Access to protected
    resources using Bearer tokens provides no authenticity of clients which means
    that a malicious party able to obtain your tokens can use them without the
    provider being able to know the difference. This is unlike OAuth 1 where a
    lost token could not be utilized without the client secret and the token
    bound secret, since they are required for the signing of each request::

        # DO NOT REGISTER A NON-HTTPS REDIRECTION URI
        # OAuthLib will raise errors if you attempt to parse a response
        # redirect back to a insecure redirection endpoint.

**Existing libraries**
    If you are using the `requests`_ HTTP library you may be interested in using
    `requests-oauthlib`_ which provides an OAuth 2 Client. This client removes much
    of the boilerplate you might otherwise need to deal with when interacting
    with OAuthLib directly.

    If you are interested in integrating OAuth 2 support into your favourite
    HTTP library you might find the requests-oauthlib implementation interesting.

    .. _`requests`: https://github.com/kennethreitz/requests
    .. _`requests-oauthlib`: https://github.com/requests/requests-oauthlib
