# -*- coding: utf-8 -*-
from oauthlib.common import urlencode
from oauthlib.oauth1.rfc5849.parameters import (
    _append_params,
    prepare_form_encoded_body,
    prepare_headers,
    prepare_request_uri_query,
)

from tests.unittest import TestCase

auth_only_params = [
    ("oauth_consumer_key", "9djdj82h48djs9d2"),
    ("oauth_token", "kkk9d7dh3k39sjv7"),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_timestamp", "137131201"),
    ("oauth_nonce", "7d8f3e4a"),
    ("oauth_signature", "bYT5CMsGcbgUdFHObYMEfcx6bsw="),
]
auth_and_data = list(auth_only_params)
auth_and_data.append(("data_param_foo", "foo"))
auth_and_data.append(("data_param_1", "1"))
realm = "testrealm"
norealm_authorization_header = " ".join(
    (
        "OAuth",
        'oauth_consumer_key="9djdj82h48djs9d2",',
        'oauth_token="kkk9d7dh3k39sjv7",',
        'oauth_signature_method="HMAC-SHA1",',
        'oauth_timestamp="137131201",',
        'oauth_nonce="7d8f3e4a",',
        'oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"',
    )
)
withrealm_authorization_header = " ".join(
    (
        "OAuth",
        'realm="testrealm",',
        'oauth_consumer_key="9djdj82h48djs9d2",',
        'oauth_token="kkk9d7dh3k39sjv7",',
        'oauth_signature_method="HMAC-SHA1",',
        'oauth_timestamp="137131201",',
        'oauth_nonce="7d8f3e4a",',
        'oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"',
    )
)


def test_append_params():
    unordered_1 = [
        ("oauth_foo", "foo"),
        ("lala", 123),
        ("oauth_baz", "baz"),
        ("oauth_bar", "bar"),
    ]
    unordered_2 = [
        ("teehee", 456),
        ("oauth_quux", "quux"),
    ]
    expected = [
        ("teehee", 456),
        ("lala", 123),
        ("oauth_quux", "quux"),
        ("oauth_foo", "foo"),
        ("oauth_baz", "baz"),
        ("oauth_bar", "bar"),
    ]
    assert _append_params(unordered_1, unordered_2) == expected


def test_prepare_headers():
    assert prepare_headers(auth_only_params, {}) == {"Authorization": norealm_authorization_header}
    assert prepare_headers(auth_only_params, {}, realm=realm) == {"Authorization": withrealm_authorization_header}


def test_prepare_headers_ignore_data():
    assert prepare_headers(auth_and_data, {}) == {"Authorization": norealm_authorization_header}
    assert prepare_headers(auth_and_data, {}, realm=realm) == {"Authorization": withrealm_authorization_header}


def test_prepare_form_encoded_body():
    existing_body = ""
    form_encoded_body = "data_param_foo=foo&data_param_1=1&oauth_consumer_key=9djdj82h48djs9d2&oauth_token=kkk9d7dh3k39sjv7&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_nonce=7d8f3e4a&oauth_signature=bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
    assert urlencode(prepare_form_encoded_body(auth_and_data, existing_body)) == form_encoded_body


def test_prepare_request_uri_query():
    url = "http://notarealdomain.com/foo/bar/baz?some=args&go=here"
    request_uri_query = "http://notarealdomain.com/foo/bar/baz?some=args&go=here&data_param_foo=foo&data_param_1=1&oauth_consumer_key=9djdj82h48djs9d2&oauth_token=kkk9d7dh3k39sjv7&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_nonce=7d8f3e4a&oauth_signature=bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
    assert prepare_request_uri_query(auth_and_data, url) == request_uri_query
