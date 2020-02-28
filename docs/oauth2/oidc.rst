OpenID Connect
==============

OpenID Connect represents a substantial set of behaviors and
interactions built on the foundations of OAuth2.  OAuthLib supports
OpenID Connect `Authentication flows`_ when the initial grant type
request's ``scope`` parameter contains ``openid``.  Providers wishing
to provide this support must implement a couple of new features within
their ``RequestValidator`` subclass.

A new userinfo endpoint can also be implemented to fulfill the core of OIDC.

.. _`Authentication flows`: http://openid.net/specs/openid-connect-core-1_0.html#Authentication

.. toctree::
   :maxdepth: 2

   oidc/validator
   oidc/endpoints
   oidc/grants
   oidc/id_tokens
