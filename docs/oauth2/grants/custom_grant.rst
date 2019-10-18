Custom Grant type
-----------------

Writing a custom grant type can be useful to implement a specification
which is in an early draft, or implement a grant provided by a
specific OAuth2.0 Authorization Server documentation but not provided
by oauthlib. For information, any grant types with a clear
specification can be integrated in oauthlib, just make a PR for that
!. See :doc:`how to contribute here </contributing>`.

Please find below an example of how to create a new grant and use it
in an endpoint:

.. contents:: Tutorial Contents
    :depth: 3


1. Define your Grant Type
-------------------------

The heart of your code is done by subclassing
:py:class:`oauthlib.oauth2.rfc6749.grant_types.base.GrantTypeBase`.
If you want to use it in the Authorize endpoint, you will have to
implement `create_authorization_response`, if in the Token endpoint,
implement `create_token_response`.


2. Associate it with Endpoints
------------------------------
Then, once declared, you have to create an instance of your grant and
add it to your
endpoint. I.e. :py:class:`oauthlib.oauth2.rfc6749.endpoints.AuthorizationEndpoint`
or :py:class:`oauthlib.oauth2.rfc6749.endpoints.TokenEndpoint`. You
can see concrete examples in
:py:class:`oauthlib.oauth2.rfc6749.endpoints.pre_configured.Server`
for examples.

3. Example
----------

To be completed.

.. code-block:: python
    class XXXZZZGrant(GrantTypeBase):
        def create_token_response(self, request, token_handler):
            if not request.grant_type == 'xxx_zzz':
                raise errors.UnsupportedGrantTypeError(request=request)
            ...
         
