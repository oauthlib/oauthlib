# -*- coding: utf-8 -*-

"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth
spec.
"""


def filter_oauth(params):
    """Removes all non oauth parameters

    :param target: A method with the first arg being params.
    """
    is_oauth = lambda kv: kv[0].startswith("oauth_")
    if isinstance(params, dict):
        return filter(is_oauth, params.items())
    else:
        return filter(is_oauth, params)
