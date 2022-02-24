Creating a Provider
===================

.. contents::
   :depth: 2

1. Create an OIDC provider
--------------------------
If you don't have an OAuth2.0 Provider, you can follow the instructions at
:doc:`OAuth2.0 Creating a Provider </oauth2/server>`. Then, follow the
migration step below.

2. Migrate your OAuth2.0 provider into an OIDC provider
-------------------------------------------------------

If you have a OAuth2.0 provider running and want to upgrade to OIDC, you can
upgrade it by replacing one line of code:

.. code-block:: python

    from oauthlib.oauth2 import Server
    from oauthlib.oauth2 import RequestValidator

Into

.. code-block:: python

    from oauthlib.openid import Server
    from oauthlib.openid import RequestValidator

Then, you have to implement the new `RequestValidator` methods as
shown below.  Note also that a new :doc:`UserInfo endpoint </oauth2/oidc/userinfo>` can be defined
and needs a new controller into your webserver.

3. Extend RequestValidator
--------------------------

A couple of methods must be implemented in your validator subclass if
you wish to support OpenID Connect:

.. autoclass:: oauthlib.openid.RequestValidator
   :members:

4. Preconfigured all-in-one servers
-----------------------------------

.. autoclass:: oauthlib.openid.connect.core.endpoints.pre_configured.Server
   :members:
