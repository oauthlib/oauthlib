Implicit Grant
--------------

.. warning::

    The Implicit grant is no longer recommended. The
    `OAuth 2.0 Security Best Current Practice`_ (RFC 9700) advises
    against it, and it is omitted from OAuth 2.1. Public clients such as
    mobile apps and single-page applications should use the
    :doc:`Authorization Code grant <authcode>` with PKCE instead.

.. _`OAuth 2.0 Security Best Current Practice`: https://tools.ietf.org/html/rfc9700

.. autoclass:: oauthlib.oauth2.ImplicitGrant
    :members:
    :inherited-members:
