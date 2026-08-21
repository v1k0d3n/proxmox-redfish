"""HTTP server for the Proxmox Redfish daemon."""

import socketserver

from .request_handler import RedfishRequestHandler


def run_server(port: int = 8000, host: str = "") -> None:
    """Run the HTTP server on the specified port.

    An empty host binds every interface, which is the historical behaviour.
    """
    server_address = (host, port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)

    print(f"Redfish server running on {host or '0.0.0.0'}:{port}...")
    httpd.serve_forever()
