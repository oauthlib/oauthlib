# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .unittest import TestCase

from oauthlib.utils import *


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
        self.assertEqual(len(nonce), 30)
        for i in range(50):
            self.assertTrue(nonce != generate_nonce())
