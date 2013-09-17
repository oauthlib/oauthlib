===========
Grant types
===========

.. toctree::
    :maxdepth: 2

    authcode
    implicit
    password
    credentials

Grant types are what make OAuth 2 so flexible. The Authorization Code grant is
very similar to OAuth 1 (with less crypto), the Implicit grant serves less
secure applications such as mobile applications, the Resource Owner Password
Credentials grant allows for legacy applications to incrementally transition to
OAuth 2, the Client Credentials grant is excellent for embedded services and
backend applications.

The main purpose of the grant types is to authorize access to protected
resources in various ways with different security credentials.

Naturally, OAuth 2 allows for extension grant types to be defined and OAuthLib
attempts to cater for easy inclusion of this as much as possible.

Certain grant types allow the issuing of refresh tokens which will allow a
client to request new tokens for as long as you as provider allow them too. In
general, OAuth 2 tokens should expire quickly and rather than annoying the user
by require them to go through the authorization redirect loop you may use the
refresh token to get a new access token. Refresh tokens, contrary to what their
name suggest, are components of a grant type rather than token types (like
Bearer tokens), much like the authorization code in the authorization code
grant.
