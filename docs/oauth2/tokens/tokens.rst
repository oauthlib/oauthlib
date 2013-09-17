======
Tokens
======

The main token type of OAuth 2 is Bearer tokens and that is what OAuthLib
currently supports. Other tokens, such as JWT, SAML and possibly MAC (if the
spec matures) can easily be added (and will be in due time).

The purpose of a token is to authorize access to protected resources to a client
(i.e. your G+ feed).

.. toctree::
    :maxdepth: 2

    bearer
    saml
    jwt
    mac
