=============
Bearer Tokens
=============

The most common OAuth 2 token type.

Bearer tokens is the default setting for all configured endpoints. Generally
you will not need to ever construct a token yourself as the provided servers
will do so for you.

By default, :doc:`*Server </oauth2/preconfigured_servers>` generate Bearer tokens as
random strings. However, you can change the default behavior to generate JWT
instead. All preconfigured servers take as parameters `token_generator` and
`refresh_token_generator` to fit your needs.

.. contents:: Tutorial Contents
    :depth: 3


1. Generate signed JWT
----------------------

A function is available to generate signed JWT (with RS256 PEM key) with static
and dynamic claims.

.. code-block:: python

    from oauthlib.oauth2.rfc6749 import tokens
    from oauthlib.oauth2 import Server

    private_pem_key = <load_your_key_in_pem_format>
    validator = <instantiate_your_validator>

    server = Server(
      your_validator,
      token_generator=tokens.signed_token_generator(private_pem_key, issuer="foobar")
    )


Note that you can add any custom claims in `RequestValidator` methods by adding them to
`request.claims` dictionary. Example below:


.. code-block:: python

    def validate_client_id(self, client_id, request):
        (.. your usual checks ..)

        request.claims = {
            'aud': self.client_id
        }
        return True


Once completed, the token endpoint will generate access_token in JWT form:

.. code-block:: shell


    access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJy(..)&expires_in=120&token_type=Bearer(..)


And you will find all claims in its decoded form:


.. code-block:: javascript

    {
      "aud": "<client_id>",
      "iss": "foobar",
      "scope": "profile calendar",
      "exp": 12345,
    }


2. Define your own implementation (text, JWT, JWE, ...)
----------------------------------------------------------------

Sometime you may want to generate custom `access_token` with a reference from a
database (as text) or use a HASH signature in JWT or use JWE (encrypted content).

Also, note that you can declare the generate function in your instanciated
validator to benefit of the `self` variables.

See the example below:

.. code-block:: python

    class YourValidator(RequestValidator):
        def __init__(self, secret, issuer):
            self.secret = secret
            self.issuer = issuer

        def generate_access_token(self, request):
            token = jwt.encode({
                "ref": str(libuuid.uuid4()),
                "aud": request.client_id,
                "iss": self.issuer,
                "exp": now + datetime.timedelta(seconds=request.expires_in)
            }, self.secret, algorithm='HS256').decode()
            return token


Then associate it to your `Server`:

.. code-block:: python

    validator = YourValidator(secret="<your_secret>", issuer="<your_issuer_id>")

    server = Server(
        your_validator,
        token_generator=validator.generate_access_token
    )


3. BearerToken API
------------------

If none of the :doc:`/oauth2/preconfigured_servers` fit your needs, you can
declare your own Endpoints and use the `BearerToken` API as below.

.. autoclass:: oauthlib.oauth2.BearerToken
    :members:
