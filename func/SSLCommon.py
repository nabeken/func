# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# Copyright 2005 Dan Williams <dcbw@redhat.com> and Red Hat, Inc.

import os, sys
from OpenSSL import SSL
import SSLConnection
import httplib
import socket
import SocketServer

def our_verify(connection, x509, errNum, errDepth, preverifyOK):
    # print "Verify: errNum = %s, errDepth = %s, preverifyOK = %s" % (errNum, errDepth, preverifyOK)

    # preverifyOK should tell us whether or not the client's certificate
    # correctly authenticates against the CA chain
    return preverifyOK


def CreateSSLContext(pkey, cert, ca_cert):
    for f in pkey, cert, ca_cert:
        if f and not os.access(f, os.R_OK):
            print "%s does not exist or is not readable." % f
            os._exit(1)

    ctx = SSL.Context(SSL.SSLv3_METHOD)   # SSLv3 only
    ctx.use_certificate_file(cert)
    ctx.use_privatekey_file(pkey)
    ctx.load_client_ca(ca_cert)
    ctx.load_verify_locations(ca_cert)
    verify = SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT
    ctx.set_verify(verify, our_verify)
    ctx.set_verify_depth(10)
    ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_TLSv1)
    return ctx



class BaseServer(SocketServer.TCPServer):
    allow_reuse_address = 1

    def __init__(self, server_addr, req_handler):
        self._quit = False
        self.allow_reuse_address = 1
        SocketServer.TCPServer.__init__(self, server_addr, req_handler)

    def stop(self):
        self._quit = True

    def serve_forever(self):
        while not self._quit:
            self.handle_request()
        self.server_close()


class BaseSSLServer(BaseServer):
    """ SSL-enabled variant """

    def __init__(self, server_address, req_handler, pkey, cert, ca_cert, timeout=None):
        self._timeout = timeout
        self.ssl_ctx = CreateSSLContext(pkey, cert, ca_cert)

        BaseServer.__init__(self, server_address, req_handler)

        port = server_address[1]
        info = socket.getaddrinfo(None, port, socket.AF_UNSPEC, self.socket_type, 0, socket.AI_PASSIVE)
        sock = socket.socket(*info[0][:3])
        con = SSL.Connection(self.ssl_ctx, sock)
        self.socket = SSLConnection.SSLConnection(con)

        if sys.version_info[:3] >= (2, 3, 0):
            self.socket.settimeout(self._timeout)

        host = self.socket.getsockname()[0]
        self.server_name = socket.getfqdn(host)
        self.server_port = port

        self.server_bind()
        self.server_activate()


class HTTPSConnection(httplib.HTTPConnection):
    "This class allows communication via SSL."

    response_class = httplib.HTTPResponse

    def __init__(self, host, port=None, ssl_context=None, strict=None, timeout=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)
        self.ssl_ctx = ssl_context
        self._timeout = timeout

    def connect(self):
        for res in socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res

            try:
                sock = socket.socket(af, socktype, proto)
                con = SSL.Connection(self.ssl_ctx, sock)
                self.sock = SSLConnection.SSLConnection(con)

                if sys.version_info[:3] >= (2, 3, 0):
                    self.sock.settimeout(self._timeout)

                self.sock.connect(sa)
            except socket.error, msg:
                if self.sock:
                    self.sock.close()
                sock = None
                continue
            break

        if not self.sock:
            raise socket.error, msg

class HTTPS(httplib.HTTP):
    """Compatibility with 1.5 httplib interface

    Python 1.5.2 did not have an HTTPS class, but it defined an
    interface for sending http requests that is also useful for
    https.
    """

    _connection_class = HTTPSConnection

    def __init__(self, host='', port=None, ssl_context=None, strict=None, timeout=None):
        self._setup(self._connection_class(host, port, ssl_context, strict, timeout))

