OAuthLib: a generic library for signing OAuth requests
======================================================

OAuth often seems complicated and difficult-to-implement. There are several
prominent libraries for signing OAuth requests, but they all suffer from one or
both of the following:

1. They predate the `OAuth 1.0 spec`_, AKA RFC 5849.
2. They assume the usage of a specific HTTP request library.

.. _`OAuth 1.0 spec`: http://tools.ietf.org/html/rfc5849

OAuthLib is a generic utility which implements the logic of OAuth without
assuming a specific HTTP request object. Use it to graft OAuth support onto your
favorite HTTP library. If you're a maintainer of such a library, write a thin
veneer on top of OAuthLib and get OAuth support for very little effort.

HTTP Libraries supporting OAuthLib
----------------------------------

* The `requests`_ library will soon have full support for OAuthLibs features. 

.. _`requests`: http://docs.python-requests.org/en/latest/

Signing requests using OAuthLib
-------------------------------

For an introduction to OAuth 1.0 please visit `hueniverse/oauth`_.

.. _`hueniverse/oauth`: http://hueniverse.com/oauth/


In order to authenticate with OAuth you need to register a third party client with an authorization server such as Twitter, Facebook or Google. Upon doing so you will receive a set of credentials which will be used when requesting access to protected resources. The credentials are sent using specific oauth parameters, which in addition needs to be signed. Different servers will provide and require different parameters depending on what authentication method you use and their preference. 

The OAuth RFC supports three places in which you can supply authentication parameters to your request.

* The Authorization header (Recommended)
* The Request URI Query
* The Form-Encoded Body

There are three ways in which you can sign a request.

* HMAC-SHA1 (Default)
* RSA-SHA1
* Plaintext



Case study: Twitter
-------------------

The study aims to show HTTP library developers how OAuthLib can be used. Using OAuthLib this way is not recommended. Instead use it indirectly through an HTTP library that uses OAuthLib, such as `requests`.

Twitter will give each client a consumer key and a consumer secret. The OAuth parameters are suplied in the authorization header and signed using HMAC-SHA1::

    client_key = "325oyusfsdfksf"
    client_secret = "43wiuyfskdf98234"
    request_url = "https://api.twitter.com/oauth/request_token"
    auth_url = "https://api.twitter.com/oauth/authorize"
    access_url = "https://api.twitter.com/oauth/access_token"

A common workflow when using OAuth is to first request access to protected resources by having the user (resource owner) authorize access. This is done by redirecting the user to an authorization url, with a request token supplied, and after the authorization is complete, requesting an access token. The access token can be stored for later use, thus it is only needed to obtain it once. 

In our example we will
 
#. Create an authorization url 
#. Receive an oauth verifier from the user (manually copy/pasted)
#. Fetch an access token
#. Tweet "Hello world"

*Note that we do not use the included OAuth features of requests.*

Creating a redirection url for user authorization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The url is constructed by adding an ``oauth_token`` parameter to the request url. We obtain the token from the response of a GET request to https://api.twitter.com/oauth/request_token.


**Crafting the authorization header using OAuthLib**::

    import oauthlib.oauth as oauth
    params = oauth.generate_params(client_key=client_key)
    signature = oauth.sign_hmac("GET", request_url, params, client_secret)
    params["oauth_signature"] = signature
    header = oauth.prepare_authorization_header(params)

*Use oauth.generate_params to create a dictionary of the required OAuth parameters. It will in addition to supplied parameters generate nonce, signature method, timestamp and version for you.*

*Note that any signature method (HMAC, SHA, Plaintext) requires type of request method, url and OAuth parameters. Client and token secrets are used with HMAC and RSA.* 

**Fetching the token using requests**::

    import requests
    headers = { "Authorization" : header }
    response = requests.get(request_url, headers=headers)

**Extracting the token from the respone**::

    from urlparse import parse_qs
    token = parse_qs(response.text)["oauth_token"][0]

*The response is an url encoded query string in the response body*

**Creating the redirection url**::

    redirect_url = "{url}?oauth_token={token}".format(url=auth_url, token=token)
    print "Please open this url and authorize access, then copy the oauth_verifier"
    print redirect_url


Allow the user to supply oauth_verifier
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We will use ``raw_input`` and have the user manually copy and paste the ``oauth_verifier``, when using a webapp rather than a command line app this step can be automated.::

    verifier = raw_input("OAuth verifier: ")
 

Fetch the access token
^^^^^^^^^^^^^^^^^^^^^^

**Crafting the authorization header**::

    callback = "http://whatever.you/registered"

    import oauthlib.oauth as oauth
    params = oauth.generate_params(client_key=client_key,
                                   request_token=token,
                                   verifier=verifier,
                                   callback=callback)
    signature = oauth.sign_hmac("GET", access_url, params, client_secret)
    params["oauth_signature"] = signature
    header = oauth.prepare_authorization_header(params)

**Fetching the token using requests**::

    import requests
    headers = { "Authorization" : header }
    response = requests.get(request_url, headers=headers)

**Extracting the access token and secret from the respone**::

    from urlparse import parse_qs
    access_token = parse_qs(response.text)["oauth_token"][0]
    token_secret = parse_qs(response.text)["oauth_token_secret"][0]


Tweet hello world
^^^^^^^^^^^^^^^^^
::

    update_url = "'http://api.twitter.com/1/statuses/update.json"
    post = { 'status': "Hello world!", 'wrap_links': True }

    import oauthlib.oauth as oauth
    params = oauth.generate_params(client_key=client_key,
                                   access_token=access_token)
    for k,v in post:
        params[k] = v
    signature = oauth.sign_hmac("GET", request_url, params, 
                                client_secret, token_secret)
    params["oauth_signature"] = signature
    header = oauth.prepare_authorization_header(params)

    import requests
    headers = { "Authorization" : header }
    response = requests.post(update_url, post, headers=headers)

*Note that to create a correct signature the POST data will need to be included in params.*

License
-------

OAuthLib is yours to use and abuse according to the terms of the BSD license.
Check the LICENSE file for full details.

