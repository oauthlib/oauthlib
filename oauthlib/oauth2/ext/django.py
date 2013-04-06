# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
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

    def _extract_params(self, request):
        log.debug('Extracting parameters from request.')
        uri = request.build_absolute_uri()
        http_method = request.method
        headers = request.META
        if 'wsgi.input' in headers:
            del headers['wsgi.input']
        if 'wsgi.errors' in headers:
            del headers['wsgi.errors']
        if 'HTTP_AUTHORIZATION' in headers:
            headers['Authorization'] = headers['HTTP_AUTHORIZATION']
        body = urlencode(request.POST.items())
        return uri, http_method, body, headers

    def pre_authorization_view(self, f):
        @functools.wraps(f)
        def wrapper(request, *args, **kwargs):
            uri, http_method, body, headers = self._extract_params(request)
            redirect_uri = request.GET.get('redirect_uri', None)
            log.debug('Found redirect uri %s.', redirect_uri)
            try:
                scopes, credentials = self._authorization_endpoint.validate_authorization_request(
                        uri, http_method, body, headers)
                log.debug('Saving credentials to session, %r.', credentials)
                request.session['oauth2_credentials'] = credentials
                kwargs['scopes'] = scopes
                kwargs.update(credentials)
                log.debug('Invoking view method, %r.', f)
                return f(request, *args, **kwargs)

            except errors.FatalClientError as e:
                log.debug('Fatal client error, redirecting to error page.')
                return HttpResponseRedirect(e.in_uri(self._error_uri))
        return wrapper

    def post_authorization_view(self, f):
        @functools.wraps(f)
        def wrapper(request, *args, **kwargs):
            uri, http_method, body, headers = self._extract_params(request)
            scopes, credentials = f(request, *args, **kwargs)
            log.debug('Fetched credentials view, %r.', credentials)
            credentials.update(request.session.get('oauth2_credentials', {}))
            log.debug('Fetched credentials from session, %r.', credentials)
            redirect_uri = credentials.get('redirect_uri')
            log.debug('Found redirect uri %s.', redirect_uri)
            try:
                url, headers, body, status = self._authorization_endpoint.create_authorization_response(
                        uri, http_method, body, headers, scopes, credentials)
                log.debug('Authorization successful, redirecting to client.')
                return HttpResponseRedirect(url)
            except errors.FatalClientError as e:
                log.debug('Fatal client error, redirecting to error page.')
                return HttpResponseRedirect(e.in_uri(self._error_uri))
            except errors.OAuth2Error as e:
                log.debug('Client error, redirecting back to client.')
                return HttpResponseRedirect(e.in_uri(redirect_uri))

        return wrapper

    def access_token_view(self, f):
        @csrf_exempt
        @functools.wraps(f)
        def wrapper(request, *args, **kwargs):
            uri, http_method, body, headers = self._extract_params(request)
            credentials = f(request, *args, **kwargs)
            log.debug('Fetched credentials view, %r.', credentials)
            url, headers, body, status = self._token_endpoint.create_token_response(
                    uri, http_method, body, headers, credentials)
            response = HttpResponse(content=body, status=status)
            for k, v in headers.items():
                response[k] = v
            return response
        return wrapper

    def protected_resource_view(self, scopes=None):
        def decorator(f):
            @csrf_exempt
            @functools.wraps(f)
            def wrapper(request, *args, **kwargs):
                uri, http_method, body, headers = self._extract_params(request)
                valid, r = self._resource_endpoint.verify_request(
                        uri, http_method, body, headers, scopes)
                kwargs.update({
                    'client': r.client,
                    'user': r.user,
                    'scopes': r.scopes
                })
                if valid:
                    return f(request, *args, **kwargs)
                else:
                    return HttpResponseForbidden()
            return wrapper
        return decorator
