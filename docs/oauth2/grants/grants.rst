===========
Grant types
===========

.. toctree::
    :maxdepth: 2

    authcode
    implicit
    password
    credentials
    refresh
    jwt
    custom_validators
    custom_grant

Grant types are what make OAuth 2 so flexible. The :doc:`Authorization
Code grant </oauth2/grants/authcode>` is the default for almost all
Web Applications, the :doc:`Implicit grant </oauth2/grants/implicit>`
serves less secure applications such as Mobile Applications or
Single-Page Applications, the :doc:`Client Credentials grant
</oauth2/grants/credentials>` is excellent for embedded services and
backend applications. We have also the :doc:`Resource Owner Password
Credentials grant </oauth2/grants/password>` when there is a high
degree of trust between the resource owner and the client, and when
other authorization grant types are not available. This is also often
used for legacy applications to incrementally transition to OAuth 2.

The main purpose of the grant types is to authorize access to protected
resources in various ways with different security credentials.

Naturally, OAuth 2 allows for extension grant types to be defined and OAuthLib
attempts to cater for easy inclusion of this as much as possible. See
:doc:`Custom Grant Type </oauth2/grants/custom_grant>`.

OAuthlib also offers hooks for registering your own :doc:`Custom
Validators </oauth2/grants/custom_validators>` for use
with the existing grant type handlers
(:py:class:`oauthlib.oauth2.rfc6749.grant_types.base.ValidatorsContainer`).
In some situations, this may be more convenient than subclassing or writing
your own extension grant type.

Certain grant types allow the issuing of refresh tokens which will allow a
client to request new tokens for as long as you as provider allow them too. In
general, OAuth 2 tokens should expire quickly and rather than annoying the user
by require them to go through the authorization redirect loop you may use the
refresh token to get a new access token. Refresh tokens, contrary to what their
name suggest, are components of a grant type (see :doc:`Refresh Token
grant </oauth2/grants/refresh>`) rather than token types (like
Bearer tokens), much like the authorization code in the authorization code
grant.
