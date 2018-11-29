OpenID Connect
=========================================

Migrate your OAuth2.0 server into an OIDC provider
----------------------------------------------------

If you have a OAuth2.0 provider running and want to upgrade to OIDC, you can
upgrade it by replacing one line of code:

.. code-block:: python

    from oauthlib.oauth2 import Server

Into

.. code-block:: python

    from oauthlib.openid import Server

Then, you have to implement the new RequestValidator methods as shown below.

RequestValidator Extension
----------------------------------------------------

A couple of methods must be implemented in your validator subclass if you wish to support OpenID Connect:

.. autoclass:: oauthlib.oauth2.RequestValidator
   :members: validate_silent_authorization, validate_silent_login, validate_user_match, get_id_token, get_authorization_code_scopes, validate_jwt_bearer_token
