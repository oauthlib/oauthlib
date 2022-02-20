Features and platforms
======================

.. contents::
   :local:

OAuth 1.0a
..........

OAuth 1.0a is fully supported for both clients and providers.

All standard *signature methods* defined in `RFC 5849`_ *The OAuth 1.0
Protocol* are supported:

- HMAC-SHA1
- RSA-SHA1
- PLAINTEXT

Non-standard *signature methods* that replaces SHA-1 with stronger
digest algorithms are also supported:

- HMAC-SHA256
- HMAC-SHA512
- RSA-SHA256
- RSA-SHA512

The OAuth 1.0a signature can be placed in the header, URL or body of
the request.

OAuth 2.0
.........

OAuth 2.0 full client and provider supports for:

- `RFC 6749 section-4.1`_: Authorization Code Grant
- `RFC 6749 section-4.2`_: Implicit Grant
- `RFC 6749 section-4.3`_: Resource Owner Password Credentials Grant
- `RFC 6749 section-4.4`_: Client Credentials Grant
- `RFC 6749 section-6`_: Refresh Tokens
- `RFC 6750`_: Bearer Tokens
- `RFC 7009`_: Token Revocation
- `RFC 7636`_: Proof Key for Code Exchange by OAuth Public Clients (PKCE)
- `RFC Draft`_ Message Authentication Code (MAC) Tokens

Only OAuth2.0 Provider has been implemented:

- `OpenID Connect Core`_
- `RFC 7662`_: Token Introspection
- `RFC 8414`_: Authorization Server Metadata

Only OAuth2.0 Client has been implemented:

- `RFC 8628`_: Device Authorization Grant

Missing features:

- SAML2
- Bearer JWT as Client Authentication
- Dynamic client registration
- OpenID Discovery
- OpenID Session Management

Any help are welcomed and will be carefully reviewed and integrated to the project. Don't hesitate to be part of the community !


Platforms
.........

OAuthLib is mainly developed and tested on 64-bit Linux. It works on
Unix and Unix-like operating systems (including macOS), as well as
Microsoft Windows.

It should work on any platform that supports Python, if features
requiring RSA public-key cryptography is not used.

If features requiring RSA public-key cryptography is used (e.g
RSA-SHA1 and RS256), it should work on any platform supported by
PyCA's `cryptography`_ package. RSA features require installing
additional packages: see the installation instructions for details.

.. _`cryptography`: https://cryptography.io/en/latest/installation/
.. _`RFC 5849`: https://tools.ietf.org/html/rfc5849
.. _`RFC 6749 section-4.1`: https://tools.ietf.org/html/rfc6749#section-4.1
.. _`RFC 6749 section-4.2`: https://tools.ietf.org/html/rfc6749#section-4.2
.. _`RFC 6749 section-4.3`: https://tools.ietf.org/html/rfc6749#section-4.3
.. _`RFC 6749 section-4.4`: https://tools.ietf.org/html/rfc6749#section-4.4
.. _`RFC 6749 section-6`: https://tools.ietf.org/html/rfc6749#section-6
.. _`RFC 6750`: https://tools.ietf.org/html/rfc6750
.. _`RFC Draft`: https://tools.ietf.org/id/draft-ietf-oauth-v2-http-mac-02.html
.. _`RFC 7009`: https://tools.ietf.org/html/rfc7009
.. _`RFC 7662`: https://tools.ietf.org/html/rfc7662
.. _`RFC 7636`: https://tools.ietf.org/html/rfc7636
.. _`RFC 8628`: https://tools.ietf.org/html/rfc8628
.. _`OpenID Connect Core`: https://openid.net/specs/openid-connect-core-1_0.html
.. _`RFC 8414`: https://tools.ietf.org/html/rfc8414
