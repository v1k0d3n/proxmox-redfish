"""HTTP server for the Proxmox Redfish daemon."""

import socketserver

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


def run_server(port: int = 8000, host: str = "") -> None:
    """Run the HTTP server on the specified port.

    An empty host binds every interface, which is the historical behaviour.
    """
    server_address = (host, port)
    httpd = _ThreadedServer(server_address, RedfishRequestHandler)

    print(f"Redfish server running on {host or '0.0.0.0'}:{port}...")
    httpd.serve_forever()
