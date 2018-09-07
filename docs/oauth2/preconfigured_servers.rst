Preconfigured all-in-one servers
================================

A pre configured server is an all-in-one endpoint serving a specific class of
application clients. As the individual endpoints, they depend on the use of a
:doc:`validator`.

Construction is simple, only import your validator and you are good to go::

    from your_validator import your_validator
    from oauthlib.oauth2 import WebApplicationServer

    server = WebApplicationServer(your_validator)

If you prefer to construct tokens yourself you may pass a token generator (see
 :doc:`Tokens <tokens/tokens>` for more examples like JWT) ::

    def your_token_generator(request, refresh_token=False):
        return 'a_custom_token' + request.client_id

    server = WebApplicationServer(your_validator, token_generator=your_token_generator)

This function is passed the request object and a boolean indicating whether to generate an access token (False) or a refresh token (True).

.. autoclass:: oauthlib.oauth2.Server
    :members:

.. autoclass:: oauthlib.oauth2.WebApplicationServer
    :members:

.. autoclass:: oauthlib.oauth2.MobileApplicationServer
    :members:

.. autoclass:: oauthlib.oauth2.LegacyApplicationServer
    :members:

.. autoclass:: oauthlib.oauth2.BackendApplicationServer
    :members:
