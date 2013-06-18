Preconfigured all-in-one servers
================================

A pre configured server is an all-in-one endpoint serving a specific class of
application clients. As the individual endpoints, they depend on the use of a
:doc:`validator`.

Construction is simple, only import your validator and you are good to go::

    from your_validator import your_validator
    from oauthlib.oauth1 import WebApplicationServer

    server = WebApplicationServer(your_validator)

All endpoints are documented in :doc:`endpoints`.

.. autoclass:: oauthlib.oauth1.WebApplicationServer
    :members:
