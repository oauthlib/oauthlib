Supported features and platforms
================================

OAuth 1 is fully supported per the RFC for both clients and providers.
Extensions and variations that are outside the spec are not supported.

- HMAC-SHA1, RSA-SHA1 and plaintext signatures.
- Signature placement in header, url or body.

OAuth 2 client and provider support for

- Authorization Code Grant
- Implicit Grant
- Client Credentials Grant
- Resource Owner Password Credentials Grant
- Refresh Tokens
- Bearer Tokens
- Draft MAC tokens
- Token Revocation
- Token Introspection
- OpenID Connect Authentication

with support for SAML2 and JWT tokens, dynamic client registration and more to
come.

Supported platforms
-------------------

OAuthLib is mainly developed/tested on 64 bit Linux but works on Unix (incl. OS
X) and Windows as well. Unless you are using the RSA features of OAuth 1 you
should be able to use OAuthLib on any platform that supports Python. If you use
RSA you are limited to the platforms supported by `cryptography`_.

.. _`cryptography`: https://cryptography.io/en/latest/installation/
