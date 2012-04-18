from __future__ import absolute_import
from oauthlib.oauth1.rfc5849 import *
from oauthlib.oauth1.rfc5849 import utils
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

    def setUp(self):
        self.server = self.TestServer()
        self.client = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
        )

    def test_basic_request(self):
        uri, body, headers = self.client.sign(u'http://server.example.com:80/init')
        headers = dict([(str(k), str(v)) for k, v in headers.iteritems()])
        self.assertTrue(self.server.check_request_signature(uri, body=body,
            headers=headers))

    def test_callback_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
            callback_uri=u'http://client.example.com/callback'
        )

        uri, body, headers = c.sign(u'http://server.example.com:80/init')
        headers = dict([(str(k), str(v)) for k, v in headers.iteritems()])
        self.assertTrue(self.server.check_request_signature(uri, body=body,
            headers=headers))

    def test_multipart_body_request(self):
        headers = {
            u'Content-Type': u'multipart/form-data; boundary=BoUnDaRyStRiNg'
        }
        body = u"--BoUnDaRyStRiNg--\n\n"

        uri, body, headers = self.client.sign(u'http://server.example.com:80/resource',
            body=body, headers=headers)

        headers = dict([(str(k), str(v)) for k, v in headers.iteritems()])
        self.assertTrue(self.server.check_request_signature(uri, body=body,
            headers=headers))

    def test_urlencoded_body_request(self):
        headers = { u'Content-Type': u'application/x-www-form-urlencoded' }
        body = u"key=value"

        uri, body, headers = self.client.sign(u'http://server.example.com:80/resource',
            body=body, headers=headers)

        headers = dict([(str(k), str(v)) for k, v in headers.iteritems()])
        self.assertTrue(self.server.check_request_signature(uri, body=body,
            headers=headers))
