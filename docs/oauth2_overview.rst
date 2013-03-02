==============================
OAuth 2: A high level overview
==============================

OAuth 2 is a very generic set of documents that leave a lot up to the implementer. It is not even a protocol, it is a framework. OAuthLib approaches this by separating the logic into three categories, endpoints, grant types and tokens.

Endpoints
---------

.. toctree::
    :maxdepth: 2

    endpoints

There are three different endpoints, the authorization endpoint which mainly handles user authorization, the token endpoint which provides tokens and the resource endpoint which provides access to protected resources. It is to the endpoints you will feed requests and get back an almost complete response. This process is simplified for you using a decorator such as the django one described later. 

The main purpose of the endpoint in OAuthLib is to figure out which grant type or token to dispatch the request to.

Grant types
-----------

.. toctree::
    :maxdepth: 2

    authcode
    implicit
    password
    credentials

Grant types are what make OAuth 2 so flexible. The Authorization Code grant is very similar to OAuth 1 (with less crypto), the Implicit grant serves less secure applications such as mobile applications, the Resource Owner Password Credentials grant allows for legacy applications to incrementally transition to OAuth 2, the Client Credentials grant is excellent for embedded services and backend applications. 

The main purpose of the grant types is to authorize access to protected resources in various ways with different security credentials.

Naturally, OAuth 2 allows for extension grant types to be defined and OAuthLib attempts to cater for easy inclusion of this as much as possible. 

Certain grant types allow the issuing of refresh tokens which will allow a client to request new tokens for as long as you as provider allow them too. In general, OAuth 2 tokens should expire quickly and rather than annoying the user by require them to go through the authorization redirect loop you may use the refresh token to get a new access token. Refresh tokens, contrary to what their name suggest, are components of a grant type rather than token types (like Bearer tokens), much like the authorization code in the authorization code grant.

Tokens
------

.. toctree::
    :maxdepth: 2

    tokens

The main token type of OAuth 2 is Bearer tokens and that is what OAuthLib currently supports. Other tokens, such as JWT, SAML and possibly MAC (if the spec matures) can easily be added (and will be in due time).

The purpose of a token is to authorize access to protected resources to a client (i.e. your G+ feed).
