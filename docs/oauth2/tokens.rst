==============
OAuth 2 Tokens
==============

------------------------
Bearer Tokens (standard)
------------------------

The most common OAuth 2 token type. It provides very little in terms of security
and relies heavily upon the ability of the client to keep the token secret.

Bearer tokens are the default setting with all configured endpoints. Generally
you will not need to ever construct a token yourself as the provided servers
will do so for you.

.. autoclass:: oauthlib.oauth2.BearerToken
    :members:

-----------
SAML Tokens
-----------

Not yet implemented. Track progress in `GitHub issue 49`_.

.. _`GitHub issue 49`: https://github.com/idan/oauthlib/issues/49

----------
JWT Tokens
----------

Not yet implemented. Track progress in `GitHub issue 50`_.

.. _`GitHub issue 50`: https://github.com/idan/oauthlib/issues/50

----------
MAC tokens
----------

Not yet implemented. Track progress in `GitHub issue 29`_. Might never be
supported depending on whether the work on the specification is resumed or not.

.. _`GitHub issue 29`: https://github.com/idan/oauthlib/issues/29
