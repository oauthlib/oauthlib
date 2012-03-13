from __future__ import absolute_import

from .unittest import TestCase

from oauthlib.utils import *


class UtilsTests(TestCase):

    def test_filter_params(self):

        @filter_params
        def special_test_function(params, realm=None):
            """ I am a special test function """
            return 'OAuth ' + ','.join(['='.join([k, v]) for k, v in params])

        # check that the docstring got through
        self.assertEqual(special_test_function.__doc__, " I am a special test function ")

        sample_params = [
                ("notoauth", "shouldnotbehere"),
                ("oauth_consumer_key", "9djdj82h48djs9d2"),
                ("oauth_token", "kkk9d7dh3k39sjv7"),
                ("notoautheither", "shouldnotbehere")
            ]

        # Check that the filtering works as per design.
        #   Any param that does not start with 'oauth'
        #   should not be present in the filtered params
        filtered_params = special_test_function(sample_params)
        self.assertFalse("notoauth" in filtered_params)
        self.assertTrue("oauth_consumer_key" in filtered_params)
        self.assertTrue("oauth_token" in filtered_params)
        self.assertFalse("notoautheither" in filtered_params)