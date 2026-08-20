"""SSL server for the Proxmox Redfish daemon."""

import os
import socketserver
import ssl

from ..config.logging_config import logger
from ..config.settings import SSL_CA_FILE, SSL_CERT_FILE, SSL_KEY_FILE
from .request_handler import RedfishRequestHandler


def run_server_ssl(port: int = 443) -> None:
    """Run the SSL server on the specified port."""
    server_address = ("", port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)

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

    print(f"Redfish server running on port {port} with SSL...")
    logger.info(f"Redfish server started on port {port} with SSL certificates")
    httpd.serve_forever()
