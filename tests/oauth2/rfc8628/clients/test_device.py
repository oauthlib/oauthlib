# -*- coding: utf-8 -*-
import os
from unittest.mock import patch

from oauthlib import signals
from oauthlib.oauth2 import DeviceClient

from tests.unittest import TestCase


class DeviceClientTest(TestCase):

    client_id = "someclientid"
    kwargs = {
        "some": "providers",
        "require": "extra arguments"
    }

    body = "not=empty"

    body_up = "not=empty&grant_type=urn:ietf:params:oauth:grant-type:device_code"
    body_code = body_up + "&device_code=somedevicecode"
    body_kwargs = body_code + "&some=providers&require=extra+arguments"

    device_code = 'somedevicecode'

    def test_request_body(self):
        client = DeviceClient(self.client_id)

        # Basic, no extra arguments
        body = client.prepare_request_body(self.device_code, body=self.body)
        self.assertFormBodyEqual(body, self.body_code)

        rclient = DeviceClient(self.client_id)
        body = rclient.prepare_request_body(self.device_code, body=self.body)
        self.assertFormBodyEqual(body, self.body_code)

        # With extra parameters
        body = client.prepare_request_body(
            self.device_code, body=self.body, **self.kwargs)
        self.assertFormBodyEqual(body, self.body_kwargs)
