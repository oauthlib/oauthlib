ID Tokens
=========

The creation of `ID Tokens`_ is ultimately done not by OAuthLib but by your ``RequestValidator`` subclass.  This is because their
content is dependent on your implementation of users, their attributes, any claims you may wish to support, as well as the
details of how you model the notion of a Client Application.  As such OAuthLib simply calls your validator's ``get_id_token``
method at the appropriate times during the authorization flow, depending on the grant type requested (Authorization Code, Implicit,
Hybrid, etc.)

.. _`ID Tokens`: http://openid.net/specs/openid-connect-core-1_0.html#IDToken

.. autoclass:: oauthlib.oauth2.RequestValidator
   :members: get_id_token



