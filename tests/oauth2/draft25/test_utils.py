from __future__ import absolute_import

from ...unittest import TestCase

from oauthlib.oauth2.draft25.utils import *


class UtilsTests(TestCase):

    def test_escape(self):
        """Assert that we are only escaping unicode"""
        self.assertRaises(ValueError, escape, "I am a string type. Not a unicode type.")
        self.assertEqual(escape(u"I am a unicode type."), u"I%20am%20a%20unicode%20type.")

    def test_generate_timestamp(self):
        """ TODO: Better test here """
        timestamp = generate_timestamp()
        self.assertTrue(isinstance(timestamp, unicode))
        self.assertTrue(int(timestamp))
        self.assertTrue(int(timestamp) > 1331672335)  # is this increasing?

    def test_generate_nonce(self):
        """ TODO: better test here """
        nonce = generate_nonce()
        for i in range(50):
            self.assertTrue(nonce != generate_nonce())

    def test_generate_token(self):
        """ TODO: better test here"""
        token = generate_token()
        self.assertEqual(len(token), 20)

        token = generate_token(length=44)
        self.assertEqual(len(token), 44)

        token = generate_token(length=6, chars="python")
        self.assertEqual(len(token), 6)
        self.assertTrue("a" not in token)

    def test_host_from_uri(self):
        """Test if hosts and ports are properly extracted from URIs.

        This should be done according to the MAC Authentication spec.
        Defaults ports should be provided when none is present in the URI.
        """
        self.assertEqual(host_from_uri(u'http://a.b-c.com:8080'), (u'a.b-c.com', u'8080'))
        self.assertEqual(host_from_uri(u'https://a.b.com:8080'), (u'a.b.com', u'8080'))
        self.assertEqual(host_from_uri(u'http://www.example.com'), (u'www.example.com', u'80'))
        self.assertEqual(host_from_uri(u'https://www.example.com'), (u'www.example.com', u'443'))

    def test_urlencode(self):
        """Ensure query components encoded properly"""
        self.assertEqual(urlencode([(u'hello', u' world')]), u'hello=%20world')
        self.assertEqual(urlencode({u'hello':  u' world'}), u'hello=%20world')
