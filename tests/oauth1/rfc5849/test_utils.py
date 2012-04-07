# -*- coding: utf-8 -*-
from __future__ import absolute_import
from oauthlib.oauth1.rfc5849.utils import *
from ...unittest import TestCase

class UtilsTests(TestCase):

    sample_params_list = [
            ("notoauth", "shouldnotbehere"),
            ("oauth_consumer_key", "9djdj82h48djs9d2"),
            ("oauth_token", "kkk9d7dh3k39sjv7"),
            ("notoautheither", "shouldnotbehere")
        ]

    sample_params_dict = {
            "notoauth":"shouldnotbehere",
            "oauth_consumer_key":"9djdj82h48djs9d2",
            "oauth_token":"kkk9d7dh3k39sjv7",
            "notoautheither":"shouldnotbehere"
        }

    sample_params_unicode_list = [
            (u"notoauth", u"shouldnotbehere"),
            (u"oauth_consumer_key", u"9djdj82h48djs9d2"),
            (u"oauth_token", u"kkk9d7dh3k39sjv7"),
            (u"notoautheither", u"shouldnotbehere")
        ]

    sample_params_unicode_dict = {
            u"notoauth":u"shouldnotbehere",
            u"oauth_consumer_key":u"9djdj82h48djs9d2",
            u"oauth_token":u"kkk9d7dh3k39sjv7",
            u"notoautheither":u"shouldnotbehere"
        }

    authorization_header = """OAuth realm="Example",
    oauth_consumer_key="9djdj82h48djs9d2",
    oauth_token="kkk9d7dh3k39sjv7",
    oauth_signature_method="HMAC-SHA1",
    oauth_timestamp="137131201",
    oauth_nonce="7d8f3e4a",
    oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D" """.strip()            


    def test_filter_params(self):

        # The following is an isolated test functon used to test the filter_params decorator.
        @filter_params
        def special_test_function(params, realm=None):
            """ I am a special test function """
            return 'OAuth ' + ','.join(['='.join([k, v]) for k, v in params])

        # check that the docstring got through
        self.assertEqual(special_test_function.__doc__, " I am a special test function ")

        # Check that the decorator filtering works as per design.
        #   Any param that does not start with 'oauth'
        #   should not be present in the filtered params
        filtered_params = special_test_function(self.sample_params_list)
        self.assertFalse("notoauth" in filtered_params)
        self.assertTrue("oauth_consumer_key" in filtered_params)
        self.assertTrue("oauth_token" in filtered_params)
        self.assertFalse("notoautheither" in filtered_params)

    def test_filter_oauth_params(self):

        # try with list
        # try with list
        # try with list
        self.assertEqual(len(self.sample_params_list), 4)

        #   Any param that does not start with 'oauth'
        #   should not be present in the filtered params
        filtered_params = filter_oauth_params(self.sample_params_list)
        self.assertEqual(len(filtered_params), 2)
        
        self.assertTrue(filtered_params[0][0].startswith('oauth'))
        self.assertTrue(filtered_params[1][0].startswith('oauth'))

        # try with dict
        # try with dict
        # try with dict
        self.assertEqual(len(self.sample_params_dict), 4)

        #   Any param that does not start with 'oauth'
        #   should not be present in the filtered params
        filtered_params = filter_oauth_params(self.sample_params_dict)
        self.assertEqual(len(filtered_params), 2)
        
        self.assertTrue(filtered_params[0][0].startswith('oauth'))
        self.assertTrue(filtered_params[1][0].startswith('oauth'))

    def test_utf8_str(self):

        # check against crazy string
        crazy_string = "àçéghîłñôßûÿž♬♨♧"
        self.assertTrue(isinstance(utf8_str(crazy_string), str))
        
        # check against crazy unicode
        crazy_unicode = utf8_str(u"àçéghîłñôßûÿž♬♨♧")
        self.assertTrue(isinstance(crazy_unicode, str))

    def test_generate_timestamp(self):
        """ TODO: Better test here """
        timestamp = generate_timestamp()
        self.assertTrue(isinstance(timestamp, unicode))
        self.assertTrue(int(timestamp))
        self.assertTrue(int(timestamp) > 1331672335) # is this increasing?

    def test_generate_nonce(self):
        """ TODO: better test here """

        nonce = generate_nonce()
        for i in range(50):
            self.assertTrue(nonce != generate_nonce())

    def test_generate_token(self):
        token = generate_token()
        self.assertEqual(len(token), 20)

        token = generate_token(length=44)
        self.assertEqual(len(token), 44)

        token = generate_token(length=6, chars="python")
        self.assertEqual(len(token), 6)
        self.assertFalse("a" in token)

    def test_escape(self):
        self.assertRaises(ValueError, escape, "I am a string type. Not a unicode type.")
        self.assertEqual(escape(u"I am a unicode type."), u"I%20am%20a%20unicode%20type.")

    def test_urlencode(self):

        self.assertEqual(urlencode(self.sample_params_unicode_list), "notoauth=shouldnotbehere&oauth_consumer_key=9djdj82h48djs9d2&oauth_token=kkk9d7dh3k39sjv7&notoautheither=shouldnotbehere")
        self.assertEqual(urlencode(self.sample_params_unicode_dict), "notoauth=shouldnotbehere&oauth_consumer_key=9djdj82h48djs9d2&oauth_token=kkk9d7dh3k39sjv7&notoautheither=shouldnotbehere")

    def test_parse_authorization_header(self):

        # make us some headers
        authorization_headers = parse_authorization_header(self.authorization_header)

        # is it a list?
        self.assertTrue(isinstance(authorization_headers, list))

        # are the internal items tuples?
        for header in authorization_headers:
            self.assertTrue(isinstance(header, tuple))

        # are the internal components of each tuple strings?
        for k,v in authorization_headers:
            self.assertTrue(isinstance(k, str))
            self.assertTrue(isinstance(v, str))

        # let's check some of the parsed headers created
        self.assertEquals(authorization_headers[1][0], "oauth_nonce")
        self.assertEquals(authorization_headers[1][1], "7d8f3e4a")
        self.assertEquals(authorization_headers[2][0], "oauth_timestamp")
        self.assertEquals(authorization_headers[2][1], "137131201")
        self.assertEquals(authorization_headers[3][0], "oauth_consumer_key")
        self.assertEquals(authorization_headers[3][1], "9djdj82h48djs9d2")

