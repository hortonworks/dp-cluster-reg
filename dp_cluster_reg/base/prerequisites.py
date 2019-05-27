"""Base implementation of a prerequisites interface."""
import socket


class BasePrerequisites(object):

    def running_on_knox_host(self):
        if self.knox_host in (socket.gethostname(), socket.getfqdn()):
            return True
        if self.knox_ip() == socket.gethostbyname(socket.gethostname()):
            return True
        hostname, aliases, ips = socket.gethostbyname_ex(socket.gethostname())
        if self.knox_host == hostname or self.knox_host in aliases or self.knox_ip() in ips:
            return True
        return False

    def knox_ip(self):
        try:
            return socket.gethostbyname(self.knox_host)
        except Exception:
            return None
