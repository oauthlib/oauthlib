# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from flask import abort, make_response, redirect, request, session
try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack
import functools
import logging
from oauthlib.common import urlencode
from oauthlib.oauth2.draft25 import errors

log = logging.getLogger('oauthlib')


class OAuth2ProviderDecorator(object):

    def __init__(self, error_uri, server=None, authorization_endpoint=None,
                 token_endpoint=None, resource_endpoint=None):
        self._authorization_endpoint = authorization_endpoint or server
        self._token_endpoint = token_endpoint or server
        self._resource_endpoint = resource_endpoint or server
        self._error_uri = error_uri

    def __getattr__(self, name):
        ctx = stack.top
        if ctx is not None:
            oauth_name = 'oauth_' + name
            try:
                return getattr(ctx, oauth_name)
            except AttributeError:
                return None
        return None

    def _set_ctx(self, name, value):
        ctx = stack.top
        if ctx is not None:
            oauth_name = 'oauth_' + name
            setattr(ctx, oauth_name, value)

    def _extract_params(self):
        log.debug('Extracting parameters from request.')
        uri = request.url
        http_method = request.method
        headers = dict(request.headers)
        if 'wsgi.input' in headers:
            del headers['wsgi.input']
        if 'wsgi.errors' in headers:
            del headers['wsgi.errors']
        if 'HTTP_AUTHORIZATION' in headers:
            headers['Authorization'] = headers['HTTP_AUTHORIZATION']
        body = urlencode(request.form.items())
        return uri, http_method, body, headers

    def pre_authorization_view(self, f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            uri, http_method, body, headers = self._extract_params()
            redirect_uri = request.args.get('redirect_uri', None)
            log.debug('Found redirect uri %s.', redirect_uri)
            try:
                scopes, credentials = self._authorization_endpoint.validate_authorization_request(
                        uri, http_method, body, headers)
                log.debug('Saving credentials to session, %r.', credentials)
                session['oauth2_credentials'] = credentials
                kwargs['scopes'] = scopes
                kwargs.update(credentials)
                log.debug('Invoking view method, %r.', f)
                return f(*args, **kwargs)

            except errors.FatalClientError as e:
                log.debug('Fatal client error, redirecting to error page.')
                return redirect(e.in_uri(self._error_uri))
        return wrapper

    def post_authorization_view(self, f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            uri, http_method, body, headers = self._extract_params()
            scopes, credentials = f(*args, **kwargs)
            log.debug('Fetched credentials view, %r.', credentials)
            credentials.update(session.get('oauth2_credentials', {}))
            log.debug('Fetched credentials from session, %r.', credentials)
            redirect_uri = credentials.get('redirect_uri')
            log.debug('Found redirect uri %s.', redirect_uri)
            try:
                url, headers, body, status = self._authorization_endpoint.create_authorization_response(
                        uri, http_method, body, headers, scopes, credentials)
                log.debug('Authorization successful, redirecting to client.')
                return redirect(url)
            except errors.FatalClientError as e:
                log.debug('Fatal client error, redirecting to error page.')
                return redirect(e.in_uri(self._error_uri))
            except errors.OAuth2Error as e:
                log.debug('Client error, redirecting back to client.')
                return redirect(e.in_uri(redirect_uri))

        return wrapper

    def access_token_view(self, f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            uri, http_method, body, headers = self._extract_params()
            credentials = f(*args, **kwargs)
            log.debug('Fetched credentials view, %r.', credentials)
            url, headers, body, status = self._token_endpoint.create_token_response(
                    uri, http_method, body, headers, credentials)
            response = make_response(body, status)
            for k, v in headers.items():
                response.headers[k] = v
            return response
        return wrapper

    def protected_resource_view(self, scopes=None, forbidden=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                try:
                    scopes_list = scopes()
                except TypeError:
                    scopes_list = scopes
                uri, http_method, body, headers = self._extract_params()
                valid, r = self._resource_endpoint.verify_request(
                        uri, http_method, body, headers, scopes_list)
                self._set_ctx('client', r.client)
                self._set_ctx('user', r.user)
                self._set_ctx('scopes', r.scopes)
                self._set_ctx('token_scopes', r.token_scopes)
                if valid:
                    return f(*args, **kwargs)
                elif forbidden is not None:
                    return forbidden()
                else:
                    abort(401)
            return wrapper
        return decorator
