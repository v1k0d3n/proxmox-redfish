"""SSL server for the Proxmox Redfish daemon."""

import os
import socketserver
import ssl

from ..config.logging_config import logger
from ..config.settings import SSL_CA_FILE, SSL_CERT_FILE, SSL_KEY_FILE
from .request_handler import RedfishRequestHandler


class _ThreadedServer(socketserver.ThreadingTCPServer):
    """Serve each request on its own thread.

    A single-threaded server answers one request at a time, so a virtual
    media transfer holds every other caller -- including one polling the
    task it was just handed -- for as long as the image takes to fetch.

    daemon_threads lets the process exit without waiting for a transfer in
    progress; allow_reuse_address avoids a restart failing while the old
    socket is still in TIME_WAIT.
    """

    daemon_threads = True
    allow_reuse_address = True


def run_server_ssl(port: int = 443, host: str = "") -> None:
    """Run the SSL server on the specified port.

    An empty host binds every interface, which is the historical behaviour.
    """
    server_address = (host, port)
    httpd = _ThreadedServer(server_address, RedfishRequestHandler)

    # Wrap the socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Check if certificate files exist
    if not os.path.exists(SSL_CERT_FILE):
        raise FileNotFoundError(f"SSL certificate file not found: {SSL_CERT_FILE}")
    if not os.path.exists(SSL_KEY_FILE):
        raise FileNotFoundError(f"SSL key file not found: {SSL_KEY_FILE}")

    # Load certificate chain
    if os.path.exists(SSL_CA_FILE):
        # Load certificate with CA bundle
        context.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
        context.load_verify_locations(cafile=SSL_CA_FILE)
        logger.info(f"SSL context loaded with certificate: {SSL_CERT_FILE}, key: {SSL_KEY_FILE}, CA: {SSL_CA_FILE}")
    else:
        # Load cert
        context.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
        logger.info(f"SSL context loaded with certificate: {SSL_CERT_FILE}, key: {SSL_KEY_FILE}")

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Redfish server running on {host or '0.0.0.0'}:{port} with SSL...")
    logger.info(f"Redfish server started on port {port} with SSL certificates")
    httpd.serve_forever()
