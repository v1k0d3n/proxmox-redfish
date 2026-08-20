"""HTTP server for the Proxmox Redfish daemon."""

import socketserver

from .request_handler import RedfishRequestHandler


def run_server(port: int = 8000) -> None:
    """Run the HTTP server on the specified port."""
    server_address = ("", port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)

    print(f"Redfish server running on port {port}...")
    httpd.serve_forever()
