Custom Validators
-----------------

The Custom validators are useful when you want to change a particular
behavior of an existing grant. That is often needed because of the
diversity of the identity software and to let the oauthlib framework to be
flexible as possible.

However, if you are looking into writing a custom grant type, please
refer to the :doc:`Custom Grant Type </oauth2/grants/custom_grant>`
instead.

Custom validators (``pre_auth``, ``post_auth``, ``pre_token`` and
``post_token``), as well as code and token modifiers registered with
``register_code_modifier`` / ``register_token_modifier``, may be either plain
functions or coroutine functions (``async def``). OAuthLib awaits the result
when it is awaitable, so a hook can use an async database session:

.. code-block:: python

    from oauthlib.oauth2 import AuthorizationCodeGrant, OAuth2Error

    def my_auth_validator(request):
        return {'myval': True}

    async def my_token_validator(request):
        # is_client_allowed: your own async lookup, e.g. with an AsyncSession
        if not await is_client_allowed(request.client_id):
            raise OAuth2Error("uh-oh")

    auth_code_grant = AuthorizationCodeGrant(request_validator,
                                             pre_auth=[my_auth_validator],
                                             post_token=[my_token_validator])

.. autoclass::
               oauthlib.oauth2.rfc6749.grant_types.base.ValidatorsContainer
    :members:
