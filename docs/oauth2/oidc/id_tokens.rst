ID Tokens
=========

The creation of `ID Tokens`_ is ultimately done not by OAuthLib but by your ``RequestValidator`` subclass.  This is because their
content is dependent on your implementation of users, their attributes, any claims you may wish to support, as well as the
details of how you model the notion of a Client Application.  As such OAuthLib simply calls your validator's ``get_id_token``
method at the appropriate times during the authorization flow, depending on the grant type requested (Authorization Code, Implicit,
Hybrid, etc.).

See examples below.

.. _`ID Tokens`: http://openid.net/specs/openid-connect-core-1_0.html#IDToken

.. autoclass:: oauthlib.oauth2.RequestValidator
   :members: get_id_token


JWT/JWS example with pyjwt library
----------------------------------

An example below using Cryptography library to load the private key and PyJWT to sign the JWT.
Note that the claims list in the "data" dict must be set accordingly to the auth request.

You can switch to jwcrypto library if you want to return JWE instead.

.. code-block:: python

  class MyValidator(RequestValidator):
    def __init__(self, **kwargs):
        with open(path.join(path.dirname(path.realpath(__file__)), "./id_rsa"), 'rb') as fd:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
            self.private_pem = serialization.load_pem_private_key(
                fd.read(),
                password=None,
                backend=default_backend()
            )

        super().__init__(self, **kwargs)

    def get_id_token(self, token, token_handler, request):
        import jwt

        data = {"nonce": request.nonce} if request.nonce is not None else {}

        for claim_key in request.claims:
            data[claim_key] = request.userattributes[claim_key]  # this must be set in another callback

        return jwt.encode(data, self.private_pem, 'RS256')
