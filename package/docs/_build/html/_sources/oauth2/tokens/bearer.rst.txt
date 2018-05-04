=============
Bearer Tokens
=============

The most common OAuth 2 token type. It provides very little in terms of security
and relies heavily upon the ability of the client to keep the token secret.

Bearer tokens are the default setting with all configured endpoints. Generally
you will not need to ever construct a token yourself as the provided servers
will do so for you.

.. autoclass:: oauthlib.oauth2.BearerToken
    :members:
