================
Using the Client
================

**Are you using requests?**

    If you are, then you should take a look at `requests-oauthlib`_ which has several
    examples of how to use OAuth1 with requests.

    .. _`requests-oauthlib`: https://github.com/requests/requests-oauthlib

**Signing a request with an HMAC-SHA1 signature (most common)**

    See `requests-oauthlib`_ for more detailed examples of going through the
    OAuth workflow. In a nutshell you will be doing three types of requests, to
    obtain a request token, to obtain an access token and to access a protected
    resource.

    Obtaining a request token will require client key and secret which are
    provided to you when registering a client with the OAuth provider::

        client = oauthlib.oauth1.Client('client_key', client_secret='your_secret')
        uri, headers, body = client.sign('http://example.com/request_token')

    You will then need to redirect to the authorization page of the OAuth
    provider, which will later redirect back with a verifier and a token secret
    parameter appended to your callback url. These will be used in addition to
    the credentials from before when obtaining an access token::

        client = oauthlib.oauth1.Client('client_key', client_secret='your_secret',
            resource_owner_key='the_request_token', resource_owner_secret='the_request_token_secret',
            verifier='the_verifier')
        uri, headers, body = client.sign('http://example.com/access_token')

    The provider will now give you an access token and a new token secret which
    you will use to access protected resources::

        client = oauthlib.oauth1.Client('client_key', client_secret='your_secret',
            resource_owner_key='the_access_token', resource_owner_secret='the_access_token_secret')
        uri, headers, body = client.sign('http://example.com/protected_resource')

    .. _`requests-oauthlib`: https://github.com/requests/requests-oauthlib

**Unicode Everywhere**

    Starting with 0.3.5 OAuthLib supports automatic conversion to unicode if you
    supply input in utf-8 encoding. If you are using another encoding you will
    have to make sure to convert all input to unicode before passing it to
    OAuthLib. Note that the automatic conversion is limited to the use of
    oauthlib.oauth1.Client.

**Request body**

    The OAuth 1 spec only covers signing of x-www-url-formencoded information.
    If you are sending some other kind of data in the body (say, multipart file
    uploads), these don't count as a body for the purposes of signing. Don't
    provide the body to Client.sign() if it isn't x-www-url-formencoded data.

    For convenience, you can pass body data in one of three ways:

    * a dictionary
    * an iterable of 2-tuples
    * a properly-formatted x-www-url-formencoded string

**RSA Signatures**

    OAuthLib supports the 'RSA-SHA1' signature but does not install the jwt or
    cryptography dependency by default. The cryptography package is much better
    supported on Windows and Mac OS X than PyCrypto, and simpler to install.
    OAuthLib uses the jwt package to smooth out its internal code.
    Users can install cryptography using pip::

        pip install jwt cryptography

    When you have cryptography and jwt installed using RSA signatures is
    similar to HMAC but differ in a few aspects. RSA signatures does not make
    use of client secrets nor resource owner secrets (token secrets) and
    requires you to specify the signature type when constructing a client::

        client = oauthlib.oauth1.Client('your client key',
            signature_method=oauthlib.oauth1.SIGNATURE_RSA,
            resource_owner_key='a token you have obtained',
            rsa_key=open('your_private_key.pem').read())


**Plaintext signatures**

    OAuthLib supports plaintext signatures and they are identical in use to
    HMAC-SHA1 signatures except that you will need to set the signature_method
    when constructing Clients::

        client = oauthlib.oauth1.Client('your client key',
            client_secret='your secret',
            resource_owner_key='a token you have obtained',
            resource_owner_secret='a token secret',
            signature_method=oauthlib.oauth1.SIGNATURE_PLAINTEXT)

**Where to put the signature? Signature types**

    OAuth 1 commonly use the Authorization header to pass the OAuth signature
    and other OAuth parameters. This is the default setting in Client and need
    not be specified. However you may also use the request url query or the
    request body to pass the parameters. You can specify this location using the
    signature_type constructor parameter, as shown below::

        >>> # Embed in Authorization header (recommended)
        >>> client = oauthlib.oauth1.Client('client_key',
                signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            )

        >>> uri, headers, body = client.sign('http://example.com/path?query=hello')
        >>> headers
        {u'Authorization': u'OAuth oauth_nonce="107143098223781054691360095427", oauth_timestamp="1360095427", oauth_version="1.0", oauth_signature_method="HMAC-SHA1", oauth_consumer_key="client_key", oauth_signature="86gpxY1DUXSBRRyWnRNJekeWEzw%3D"'}

        >>> # Embed in url query
        >>> client = oauthlib.oauth1.Client('client_key',
                signature_type=SIGNATURE_TYPE_QUERY,
            )

        >>> uri, headers, body = client.sign('http://example.com/path?query=hello')
        >>> uri
        http://example.com/path?query=hello&oauth_nonce=97599600646423262881360095509&oauth_timestamp=1360095509&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=client_key&oauth_signature=VQAib%2F4uRPwfVmCZkgSE3q2p7zU%3D

        >>> # Embed in body
        >>> client = oauthlib.oauth1.Client('client_key',
                signature_type=SIGNATURE_TYPE_BODY,
            )

        >>> # Please set content-type to application/x-www-form-urlencoded
        >>> headers = {'Content-Type':oauthlib.oauth1.CONTENT_TYPE_FORM_URLENCODED}
        >>> uri, headers, body = client.sign('http://example.com/path?query=hello',
                                             headers=headers)
        >>> body
        u'oauth_nonce=148092408248153282511360095722&oauth_timestamp=1360095722&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=client_key&oauth_signature=5IKjrRKU3%2FIduI9UumVI%2FbQ0Hv0%3D'
