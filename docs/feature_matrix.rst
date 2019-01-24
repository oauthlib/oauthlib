Supported features and platforms
================================

OAuth 1 is fully supported per the RFC for both clients and providers.
Extensions and variations that are outside the spec are not supported.

- HMAC-SHA1, RSA-SHA1 and plaintext signatures.
- Signature placement in header, url or body.

OAuth 2.0 client and provider support for:

- `RFC6749#section-4.1`_: Authorization Code Grant
- `RFC6749#section-4.2`_: Implicit Grant
- `RFC6749#section-4.3`_: Resource Owner Password Credentials Grant
- `RFC6749#section-4.4`_: Client Credentials Grant
- `RFC6749#section-6`_: Refresh Tokens
- `RFC6750`_: Bearer Tokens
- `RFC7009`_: Token Revocation
- `RFC Draft MAC tokens`_
- OAuth2.0 Provider: `OpenID Connect Core`_
- OAuth2.0 Provider: `RFC7636`_: Proof Key for Code Exchange by OAuth Public Clients (PKCE)
- OAuth2.0 Provider: `RFC7662`_: Token Introspection
- OAuth2.0 Provider: `RFC8414`_: Authorization Server Metadata

Features to be implemented (any help/PR are welcomed):

- OAuth2.0 **Client**: `OpenID Connect Core`_
- OAuth2.0 **Client**: `RFC7636`_: Proof Key for Code Exchange by OAuth Public Clients (PKCE)
- OAuth2.0 **Client**: `RFC7662`_: Token Introspection
- OAuth2.0 **Client**: `RFC8414`_: Authorization Server Metadata
- SAML2
- Bearer JWT as Client Authentication
- Dynamic client registration
- OpenID Discovery
- OpenID Session Management
- ...and more

Supported platforms
-------------------

OAuthLib is mainly developed/tested on 64 bit Linux but works on Unix (incl. OS
X) and Windows as well. Unless you are using the RSA features of OAuth 1 you
should be able to use OAuthLib on any platform that supports Python. If you use
RSA you are limited to the platforms supported by `cryptography`_.

.. _`cryptography`: https://cryptography.io/en/latest/installation/
.. _`RFC6749#section-4.1`: https://tools.ietf.org/html/rfc6749#section-4.1
.. _`RFC6749#section-4.2`: https://tools.ietf.org/html/rfc6749#section-4.2
.. _`RFC6749#section-4.3`: https://tools.ietf.org/html/rfc6749#section-4.3
.. _`RFC6749#section-4.4`: https://tools.ietf.org/html/rfc6749#section-4.4
.. _`RFC6749#section-6`: https://tools.ietf.org/html/rfc6749#section-6
.. _`RFC6750`: https://tools.ietf.org/html/rfc6750
.. _`RFC Draft MAC tokens`: https://tools.ietf.org/id/draft-ietf-oauth-v2-http-mac-02.html
.. _`RFC7009`: https://tools.ietf.org/html/rfc7009
.. _`RFC7662`: https://tools.ietf.org/html/rfc7662
.. _`RFC7636`: https://tools.ietf.org/html/rfc7636
.. _`OpenID Connect Core`: https://openid.net/specs/openid-connect-core-1_0.html
.. _`RFC8414`: https://tools.ietf.org/html/rfc8414
