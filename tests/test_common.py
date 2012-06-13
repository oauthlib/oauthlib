# -*- coding: utf-8 -*-
from __future__ import absolute_import
from oauthlib.common import *
from .unittest import TestCase


class CommonTests(TestCase):
    params_dict = {u'foo': u'bar', u'baz': u'123', }
    params_twotuple = [(u'foo', u'bar'), (u'baz', u'123')]
    params_formencoded = u'foo=bar&baz=123'
    uri = u'http://www.someuri.com'

    def test_urldecode(self):
        self.assertEqual(urldecode(u''), [])
        self.assertEqual(urldecode(u'='), [(u'', u'')])
        self.assertEqual(urldecode(u'%20'), [(u' ', u'')])
        self.assertEqual(urldecode(u'+'), [(u' ', u'')])
        self.assertEqual(urldecode(u'c2'), [(u'c2', u'')])
        self.assertEqual(urldecode(u'c2='), [(u'c2', u'')])
        self.assertEqual(urldecode(u'foo=bar'), [(u'foo', u'bar')])
        self.assertEqual(urldecode(u'foo_%20~=.bar-'), [(u'foo_ ~', u'.bar-')])
        self.assertRaises(ValueError, urldecode, u'foo bar')
        self.assertRaises(ValueError, urldecode, u'?')
        self.assertRaises(ValueError, urldecode, u'%R')
        self.assertRaises(ValueError, urldecode, u'%RA')
        self.assertRaises(ValueError, urldecode, u'%AR')
        self.assertRaises(ValueError, urldecode, u'%RR')

    def test_extract_params_dict(self):
        self.assertEqual(extract_params(self.params_dict), self.params_twotuple)

    def test_extract_params_twotuple(self):
        self.assertEqual(extract_params(self.params_twotuple), self.params_twotuple)

    def test_extract_params_formencoded(self):
        self.assertEqual(extract_params(self.params_formencoded), self.params_twotuple)

    def test_extract_params_blank_string(self):
        self.assertEqual(extract_params(''), [])

    def test_extract_params_empty_list(self):
        self.assertEqual(extract_params([]), [])

    def test_extract_non_formencoded_string(self):
        self.assertEqual(extract_params('not a formencoded string'), None)

    def test_extract_invalid(self):
        self.assertEqual(extract_params(object()), None)

    def test_none_body(self):
        r = Request(self.uri)
        self.assertEqual(r.decoded_body, None)

    def test_empty_list_body(self):
        r = Request(self.uri, body=[])
        self.assertEqual(r.decoded_body, [])

    def test_empty_dict_body(self):
        r = Request(self.uri, body={})
        self.assertEqual(r.decoded_body, [])

    def test_empty_string_body(self):
        r = Request(self.uri, body='')
        self.assertEqual(r.decoded_body, [])

    def test_non_formencoded_string_body(self):
        body = 'foo bar baz la la la!'
        r = Request(self.uri, body=body)
        self.assertEqual(r.decoded_body, None)

    def test_param_free_sequence_body(self):
        body = [1, 1, 2, 3, 5, 8, 13]
        r = Request(self.uri, body=body)
        self.assertEqual(r.decoded_body, None)

    def test_list_body(self):
        r = Request(self.uri, body=self.params_twotuple)
        self.assertEqual(r.decoded_body, self.params_twotuple)

    def test_dict_body(self):
        r = Request(self.uri, body=self.params_dict)
        self.assertEqual(r.decoded_body, self.params_twotuple)

    def test_generate_timestamp(self):
        """ TODO: Better test here """
        timestamp = generate_timestamp()
        self.assertIsInstance(timestamp, unicode)
        self.assertTrue(int(timestamp))
        self.assertGreater(int(timestamp), 1331672335)  # is this increasing?

    def test_generate_nonce(self):
        """ TODO: better test here """

        nonce = generate_nonce()
        for i in range(50):
            self.assertNotEqual(nonce, generate_nonce())

    def test_generate_token(self):
        token = generate_token()
        self.assertEqual(len(token), 30)

        token = generate_token(length=44)
        self.assertEqual(len(token), 44)

        token = generate_token(length=6, chars="python")
        self.assertEqual(len(token), 6)
        self.assertNotIn("a", token)
