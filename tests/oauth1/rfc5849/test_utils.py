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
            "notoauth": "shouldnotbehere",
            "oauth_consumer_key": "9djdj82h48djs9d2",
            "oauth_token": "kkk9d7dh3k39sjv7",
            "notoautheither": "shouldnotbehere"
        }

    sample_params_unicode_list = [
            (u"notoauth", u"shouldnotbehere"),
            (u"oauth_consumer_key", u"9djdj82h48djs9d2"),
            (u"oauth_token", u"kkk9d7dh3k39sjv7"),
            (u"notoautheither", u"shouldnotbehere")
        ]

    sample_params_unicode_dict = {
            u"notoauth": u"shouldnotbehere",
            u"oauth_consumer_key": u"9djdj82h48djs9d2",
            u"oauth_token": u"kkk9d7dh3k39sjv7",
            u"notoautheither": u"shouldnotbehere"
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
        self.assertNotIn("notoauth", filtered_params)
        self.assertIn("oauth_consumer_key", filtered_params)
        self.assertIn("oauth_token", filtered_params)
        self.assertNotIn("notoautheither", filtered_params)

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

    def test_escape(self):
        self.assertRaises(ValueError, escape, "I am a string type. Not a unicode type.")
        self.assertEqual(escape(u"I am a unicode type."), u"I%20am%20a%20unicode%20type.")
        self.assertIsInstance(escape(u"I am a unicode type."), unicode)

    def test_unescape(self):
        self.assertRaises(ValueError, unescape, "I am a string type. Not a unicode type.")
        self.assertEqual(unescape(u"I%20am%20a%20unicode%20type."), u'I am a unicode type.')
        self.assertIsInstance(unescape(u"I%20am%20a%20unicode%20type."), unicode)

    def test_parse_authorization_header(self):
        # make us some headers
        authorization_headers = parse_authorization_header(self.authorization_header)

        # is it a list?
        self.assertIsInstance(authorization_headers, list)

        # are the internal items tuples?
        for header in authorization_headers:
            self.assertIsInstance(header, tuple)

        # are the internal components of each tuple unicode?
        for k, v in authorization_headers:
            self.assertIsInstance(k, unicode)
            self.assertIsInstance(v, unicode)

        # let's check the parsed headers created
        correct_headers = [
            (u"oauth_nonce", u"7d8f3e4a"),
            (u"oauth_timestamp", u"137131201"),
            (u"oauth_consumer_key", u"9djdj82h48djs9d2"),
            (u'oauth_signature', u'djosJKDKJSD8743243%2Fjdk33klY%3D'),
            (u'oauth_signature_method', u'HMAC-SHA1'),
            (u'oauth_token', u'kkk9d7dh3k39sjv7'),
            (u'realm', u'Example')]
        self.assertItemsEqual(authorization_headers, correct_headers)
