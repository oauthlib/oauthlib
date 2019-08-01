OpenID Connect
=========================================

Migrate your OAuth2.0 server into an OIDC provider
----------------------------------------------------

If you have a OAuth2.0 provider running and want to upgrade to OIDC, you can
upgrade it by replacing one line of code:

.. code-block:: python

    from oauthlib.oauth2 import Server
    from oauthlib.oauth2 import RequestValidator

Into

.. code-block:: python

    from oauthlib.openid import Server
    from oauthlib.openid import RequestValidator

Then, you have to implement the new RequestValidator methods as shown below.
Note that a new UserInfo endpoint is defined and need a new controller into your webserver.

RequestValidator Extension
----------------------------------------------------

A couple of methods must be implemented in your validator subclass if you wish to support OpenID Connect:

.. autoclass:: oauthlib.openid.RequestValidator
   :members:
