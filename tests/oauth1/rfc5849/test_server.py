from __future__ import absolute_import
from oauthlib.oauth1.rfc5849 import *
from ...unittest import TestCase


class ServerTests(TestCase):

    CLIENT_KEY = u'dpf43f3p2l4k3l03'
    CLIENT_SECRET = u'kd94hf93k423kf44'

    RESOURCE_OWNER_KEY = u'kkk9d7dh3k39sjv7'
    RESOURCE_OWNER_SECRET = u'just-a-string    asdasd'

    class TestServer(Server):
        def get_client_secret(self, client_key):
            return ServerTests.CLIENT_SECRET

        def get_resource_owner_secret(self, resource_owner_key):
            return ServerTests.RESOURCE_OWNER_SECRET

        def check_client_key(self, client_key):
            return ServerTests.CLIENT_KEY == client_key

        def check_resource_owner_key(self, client_key, resource_owner_key):
            return (ServerTests.CLIENT_KEY == client_key and
                    ServerTests.RESOURCE_OWNER_KEY == resource_owner_key)

        def check_timestamp_and_nonce(self, timestamp, nonce):
            return True

    def test_basic_server_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
        )

        uri, headers, body = c.sign(u'http://server.example.com:80/init')

        s = self.TestServer()
        self.assertTrue(s.check_request_signature(uri, body=body,
            headers=headers))

    def test_server_callback_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
            callback_uri=u'http://client.example.com/callback'
        )

        uri, headers, body = c.sign(u'http://server.example.com:80/init')

        s = self.TestServer()
        self.assertTrue(s.check_request_signature(uri, body=body,
            headers=headers))
