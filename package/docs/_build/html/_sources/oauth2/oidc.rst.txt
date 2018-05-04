OpenID Connect
==============

OpenID Connect represents a substantial set of behaviors and interactions built on the foundations of OAuth2.  OAuthLib supports
OpenID Connect `Authentication flows`_ when the initial grant type request's ``scope`` parameter contains ``openid``.  Clients wishing
to provide this support must implement several new features within their ``RequestValidator`` subclass.

.. _`Authentication flows`: http://openid.net/specs/openid-connect-core-1_0.html#Authentication

.. toctree::
   :maxdepth: 2

   oidc/id_tokens
   oidc/validator


