Custom Validators
-----------------

The Custom validators are useful when you want to change a particular
behavior of an existing grant. That is often needed because of the
diversity of the identity software and to let the oauthlib framework to be
flexible as possible.

However, if you are looking into writing a custom grant type, please
refer to the :doc:`Custom Grant Type </oauth2/grants/custom_grant>`
instead.

.. autoclass::
               oauthlib.oauth2.rfc6749.grant_types.base.ValidatorsContainer
    :members:
