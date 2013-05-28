from __future__ import unicode_literals


class InvalidClientIdentifier(Exception):
    def __init__(self, client_identifier):
        self.client_identifier = client_identifier

    def __unicode__(self):
        return 'Invalid client identifier: {0}'.format(self.client_identifer)

    def __str__(self):
        return unicode(self).encode('utf-8')


class MissingRedirectURI(Exception):
    pass


class InvalidRedirectURI(Exception):
    pass
