======
Tokens
======

The main token type of OAuth 2 is Bearer tokens and that is what OAuthLib
currently supports. Other tokens, such as SAML and MAC can easily be added.

The purpose of a token is to authorize access to protected resources to a client
(i.e. your G+ feed).

The spec `requires`_ a ``token_type`` in access token responses, but some
providers, notably Facebook, do not provide this information. Per the
`robustness principle`_, we default to the ``Bearer`` token type if this value
is missing. You can force a ``MissingTokenTypeError`` exception instead, by
setting ``OAUTHLIB_STRICT_TOKEN_TYPE`` in the environment.

.. _requires: https://tools.ietf.org/html/rfc6749#section-5.1
.. _robustness principle: https://en.wikipedia.org/wiki/Robustness_principle

.. toctree::
    :maxdepth: 2

    bearer
    saml
    mac
