import base64
import ssl
import json
import socket

from urlparse import urlparse
from dp_cluster_reg.exceptions import UnexpectedHttpCode

class Url:
    @classmethod
    def base(cls, protocol, host, port):
        return cls('%s://%s:%s' % (protocol, host, port))

    def __init__(self, url_str):
        self.base = url_str.rstrip('/')

    def __div__(self, suffix_url):
        suffix_str = str(suffix_url)
        if self._is_absolute(suffix_str):
            return Url(suffix_str)
        else:
            return Url(
                self.base + (suffix_str if suffix_str.startswith('/') else '/' + suffix_str))  # noqa

    def _is_absolute(self, suffix_str):
        return suffix_str.startswith(self.base)

    def query_params(self, **params):
        return Url(self.base + '?' + '&'.join('%s=%s' % (name, value)
                                              for name, value in params.items()))  # noqa

    def netloc(self):
        return urlparse(self.base).netloc

    def protocol(self, default='http'):
        scheme = urlparse(self.base).scheme
        return scheme if scheme else default

    def ip_address(self):
        if self.netloc():
            return socket.gethostbyname(self.netloc().split(':')[0])
        else:
            return None  # might be relative URL

    def port(self, default=80):
        netloc = self.netloc()
        return int(netloc.split(':')[1]) if ':' in netloc else default

    def __str__(self):
        return self.base


class SslContext:
    def build(self):
        if not hasattr(ssl, 'SSLContext'):
            return None
        return ssl.SSLContext(self._protocol()) if self._protocol(
        ) else ssl.create_default_context()

    def _protocol(self):
        if hasattr(ssl, 'PROTOCOL_TLS'):
            return ssl.PROTOCOL_TLS
        elif hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            return ssl.PROTOCOL_TLSv1_2
        elif hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            return ssl.PROTOCOL_TLSv1_1
        elif hasattr(ssl, 'PROTOCOL_TLSv1'):
            return ssl.PROTOCOL_TLSv1
        else:
            return None


class PermissiveSslContext:
    def build(self):
        context = SslContext().build()
        if hasattr(context, '_https_verify_certificates'):
            context._https_verify_certificates(False)
        if (hasattr(context, 'verify_mode')):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context


class Header:
    @classmethod
    def csrf(cls):
        return cls('X-Requested-By', 'ambari')

    @classmethod
    def accept(cls, content_types):
        return cls('Accept', ', '.join(content_types))

    @classmethod
    def accept_json(cls):
        return cls.accept(['application/json'])

    @classmethod
    def content_type(cls, content_type):
        return cls('Content-Type', content_type)

    @classmethod
    def cookies(cls, a_dict):
        return cls('Cookie', '; '.join('='.join(each)
                                       for each in a_dict.items()))

    def __init__(self, key, value):
        self.key, self.value = key, value

    def add_to(self, request):
        request.add_header(self.key, self.value)


class Credentials:
    @staticmethod
    def empty():
        class EmptyCredentials:
            def add_to(self, request): pass
        return EmptyCredentials()

    def __init__(self, user, password):
        self.user = user
        self.password = password
        self.header = Header(
            'Authorization',
            'Basic %s' %
            base64.encodestring(
                '%s:%s' %
                (user,
                 password)).replace(
                '\n',
                ''))

    def add_to(self, request):
        self.header.add_to(request)


class JsonTransformer:
    def __call__(self, url, code, data):
        if 200 <= code <= 299:
            return code, self._parse(data)
        else:
            raise UnexpectedHttpCode(
                'Unexpected HTTP code: %d url: %s response: %s' %
                (code, url, data))

    def _parse(self, a_str):
        if not a_str:
            return {}
        try:
            return json.loads(a_str)
        except ValueError as e:
            raise ValueError('Error %s while parsing: %s' % (e, a_str))
