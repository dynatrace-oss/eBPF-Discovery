import http.server
import ssl
import sys


def run_http_server(ip_addr, port, certfile):
    httpd = http.server.HTTPServer(
        (ip_addr, port), http.server.SimpleHTTPRequestHandler
    )
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=certfile)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


if __name__ == "__main__":
    run_http_server(sys.argv[1], int(sys.argv[2]), sys.argv[3])
