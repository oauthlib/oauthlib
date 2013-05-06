Preconfigured all-in-one servers
================================

A pre configured server is an all-in-one endpoint serving a specific class of
application clients. As the individual endpoints, they depend on the use of a
:doc:`validator`.

Once constructed they can be plugged into any of the available :doc:`decorators`
or used on their own. For the latter case you might be interested in looking at
:doc:`endpoints`.

Construction is simple, only import your validator and you are good to go::

    from your_validator import your_validator
    from oauthlib.oauth2 import WebApplicationServer

    server = WebApplicationServer(your_validator)

If you prefer to construct tokens yourself you may pass a token generator::

    def your_token_generator(request):
        return 'a_custom_token' + request.client_id

    server = WebApplicationServer(your_validator, token_generator=your_token_generator)

.. autoclass:: oauthlib.oauth2.draft25.WebApplicationServer
    :members:

.. autoclass:: oauthlib.oauth2.draft25.MobileApplicationServer
    :members:

.. autoclass:: oauthlib.oauth2.draft25.LegacyApplicationServer
    :members:

.. autoclass:: oauthlib.oauth2.draft25.BackendApplicationServer
    :members:
