# -*- coding: utf-8 -*-
from __future__ import absolute_import
from oauthlib.common import extract_params, Request
from .unittest import TestCase


class CommonTests(TestCase):
    params_dict = {u'foo': u'bar', u'baz': u'123', }
    params_twotuple = [(u'foo', u'bar'), (u'baz', u'123')]
    params_formencoded = u'foo=bar&baz=123'
    uri = u'http://www.someuri.com'

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
        self.assertEqual(r.body, [])
        self.assertEqual(r.body_has_params, False)

    def test_empty_list_body(self):
        r = Request(self.uri, body=[])
        self.assertEqual(r.body, [])
        self.assertEqual(r.body_has_params, False)

    def test_empty_dict_body(self):
        r = Request(self.uri, body={})
        self.assertEqual(r.body, [])
        self.assertEqual(r.body_has_params, False)

    def test_empty_string_body(self):
        r = Request(self.uri, body='')
        self.assertEqual(r.body, [])
        self.assertEqual(r.body_has_params, False)

    def test_non_formencoded_string_body(self):
        body = 'foo bar baz la la la!'
        r = Request(self.uri, body=body)
        self.assertEqual(r.body, body)
        self.assertEqual(r.body_has_params, False)

    def test_param_free_sequence_body(self):
        body = [1, 1, 2, 3, 5, 8, 13]
        r = Request(self.uri, body=body)
        self.assertEqual(r.body, body)
        self.assertEqual(r.body_has_params, False)

    def test_list_body(self):
        r = Request(self.uri, body=self.params_twotuple)
        self.assertEqual(r.body, self.params_twotuple)
        self.assertEqual(r.body_has_params, True)

    def test_dict_body(self):
        r = Request(self.uri, body=self.params_dict)
        self.assertEqual(r.body, self.params_twotuple)
        self.assertEqual(r.body_has_params, True)
