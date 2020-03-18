# Tested with Python 3.7+ (Mac OS X)
import io
import socket
import sys
import os
import errno
import signal
import select
from multiprocessing import Process


class WSGIServer(object):

    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    request_queue_size = 1024

    def __init__(self, server_address):
        # Create a listening socket
        self.listen_socket = listen_socket = socket.socket(
            self.address_family,
            self.socket_type
        )
        # Allow to reuse the same address
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.setblocking(0)
        # Bind
        listen_socket.bind(server_address)
        # Activate
        listen_socket.listen(self.request_queue_size)
        # Get server host name and port
        host, port = self.listen_socket.getsockname()[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port
        # Return headers set by Web framework/Web application
        self.headers_set = []

    def set_app(self, application):
        self.application = application

    def serve_forever(self):
        rlist, wlist, elist = [self.listen_socket], [], []

        # listen_socket = self.listen_socket
        while True:
            readables, writables, exceptions = select.select(rlist, wlist, elist)
            for sock in readables:
                if sock is self.listen_socket:
                    try:
                        conn, client_address = self.listen_socket.accept()
                    except IOError as e:
                        code, msg = e.args
                        if code == errno.EINTR:
                            continue
                        else:
                            raise
                    rlist.append(conn)
                else:
                    try:
                        request_data = sock.recv(1024)
                    except ConnectionResetError as e:
                        request_data = None
                    if not request_data:
                        sock.close()
                        rlist.remove(sock)
                    else:
                        request_data = request_data.decode('utf-8')
                        print(''.join(
                            f'< {line}\n' for line in request_data.splitlines()
                        ))
                        # parse request
                        (request_method, path, request_version) = self.parse_request(request_data)
                        env = self.get_environ(
                            request_data, request_method, path,
                            self.server_name, self.server_port
                        )
                        result = self.application(env, self.start_response)
                        self.finish_response(result, sock)

    @classmethod
    def parse_request(cls, text):
        request_line = text.splitlines()[0]
        request_line = request_line.rstrip('\r\n')
        # Break down the request line into components
        # (self.request_method,  # GET
        #  self.path,            # /hello
        #  self.request_version  # HTTP/1.1
        #  ) = request_line.split()
        return request_line.split()

    def get_environ(self, request_data, request_method, path, server_name, server_port):
        env = {}
        # The following code snippet does not follow PEP8 conventions
        # but it's formatted the way it is for demonstration purposes
        # to emphasize the required variables and their values
        #
        # Required WSGI variables
        env['wsgi.version']      = (1, 0)
        env['wsgi.url_scheme']   = 'http'
        env['wsgi.input']        = io.StringIO(request_data)
        env['wsgi.errors']       = sys.stderr
        env['wsgi.multithread']  = False
        env['wsgi.multiprocess'] = False
        env['wsgi.run_once']     = False
        # Required CGI variables
        env['REQUEST_METHOD']    = request_method    # GET
        env['PATH_INFO']         = path              # /hello
        env['SERVER_NAME']       = server_name       # localhost
        env['SERVER_PORT']       = str(server_port)  # 8888
        return env

    def start_response(self, status, response_headers, exc_info=None):
        # Add necessary server headers
        server_headers = [
            ('Date', 'Mon, 15 Jul 2019 5:54:48 GMT'),
            ('Server', 'WSGIServer 0.2'),
        ]
        self.headers_set = [status, response_headers + server_headers]
        # To adhere to WSGI specification the start_response must return
        # a 'write' callable. We simplicity's sake we'll ignore that detail
        # for now.
        # return self.finish_response

    def finish_response(self, result, conn):
        status, response_headers = self.headers_set
        response = f'HTTP/1.1 {status}\r\n'
        for header in response_headers:
            response += '{0}: {1}\r\n'.format(*header)
        response += '\r\n'
        for data in result:
            response += data.decode('utf-8')
        # Print formatted response data a la 'curl -v'
        print(''.join(
            f'> {line}\n' for line in response.splitlines()
        ))
        response_bytes = response.encode()
        conn.sendall(response_bytes)

SERVER_ADDRESS = (HOST, PORT) = '', 8888


def make_server(server_address, application):
    server = WSGIServer(server_address)
    server.set_app(application)
    return server


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('Provide a WSGI application object as module:callable')
    app_path = sys.argv[1]
    module, application = app_path.split(':')
    module = __import__(module)
    application = getattr(module, application)
    httpd = make_server(SERVER_ADDRESS, application)
    print(f'WSGIServer: Serving HTTP on port {PORT} ...\n')
    httpd.serve_forever()