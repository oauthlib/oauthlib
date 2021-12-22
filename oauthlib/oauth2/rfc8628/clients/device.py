# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc8628
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 Device Authorization RFC8628.
"""

from oauthlib.oauth2 import BackendApplicationClient, Client
from oauthlib.oauth2.rfc6749.parameters import prepare_token_request


class DeviceClient(Client):

    """A public client utilizing the device authorization workflow.

    The client can request an access token using a device code and
    a public client id associated with the device code as defined
    in RFC8628.

    The device authorization grant type can be used to obtain both
    access tokens and refresh tokens and is intended to be used in
    a scenario where the device being authorized does not have a
    user interface that is suitable for performing authentication.
    """

    grant_type = 'urn:ietf:params:oauth:grant-type:device_code'

    def prepare_request_body(self, device_code, body='', scope=None,
                             include_client_id=False, **kwargs):
        """Add device_code to request body

        The client makes a request to the token endpoint by adding the
        device_code as a parameter using the
        "application/x-www-form-urlencoded" format to the HTTP request
        body.

        :param body: Existing request body (URL encoded string) to embed parameters
                     into. This may contain extra paramters. Default ''.
        :param scope:   The scope of the access request as described by
                        `Section 3.3`_.

        :param include_client_id: `True` to send the `client_id` in the
                                  body of the upstream request. This is required
                                  if the client is not authenticating with the
                                  authorization server as described in
                                  `Section 3.2.1`_. False otherwise (default).
        :type include_client_id: Boolean

        :param kwargs:  Extra credentials to include in the token request.

        The prepared body will include all provided device_code as well as
        the ``grant_type`` parameter set to
        ``urn:ietf:params:oauth:grant-type:device_code``::

            >>> from oauthlib.oauth2 import BackendApplicationClient
            >>> client = DeviceClient('your_id', 'your_code')
            >>> client.prepare_request_body(scope=['hello', 'world'])
            'grant_type=urn:ietf:params:oauth:grant-type:device_code&scope=hello+world'

        .. _`Section 3.4`: https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
        """

        kwargs['client_id'] = self.client_id
        kwargs['include_client_id'] = include_client_id
        scope = self.scope if scope is None else scope
        return prepare_token_request(self.grant_type, body=body, device_code=device_code,
                                     scope=scope, **kwargs)
