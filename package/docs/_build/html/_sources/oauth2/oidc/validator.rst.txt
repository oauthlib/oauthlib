RequestValidator Extensions
============================

Four methods must be implemented in your validator subclass if you wish to support OpenID Connect:

.. autoclass:: oauthlib.oauth2.RequestValidator
   :members: validate_silent_authorization, validate_silent_login, validate_user_match, get_id_token
