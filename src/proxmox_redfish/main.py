#!/usr/bin/env python3
"""
Proxmox Redfish Daemon

A Redfish API daemon for managing Proxmox VMs, providing a standardized interface
for VM operations through the Redfish protocol.
"""

import argparse
import os
import sys

from .config.logging_config import logger, setup_logging
from .server.http_server import run_server
from .server.ssl_server import run_server_ssl

# Historical default, kept so an existing deployment that relies on it is
# unaffected.
DEFAULT_PORT = 8443


def main() -> None:
    """Main entry point for the proxmox-redfish daemon."""
    parser = argparse.ArgumentParser(description="Proxmox Redfish Daemon - Redfish API for Proxmox VMs")
    parser.add_argument(
        "--log-level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        help="Logging level. Overrides REDFISH_LOG_LEVEL.",
    )
    parser.add_argument(
        "--port",
        type=int,
        help=f"Port to listen on. Overrides REDFISH_PORT. Default {DEFAULT_PORT}.",
    )
    parser.add_argument(
        "--host",
        help="Address to bind to. Overrides REDFISH_HOST. Default is every interface.",
    )

    args = parser.parse_args()

    setup_logging(args.log_level)

    # Settings are read from the environment when config.settings is imported,
    # so that is the one place configuration comes from.
    if not os.getenv("PROXMOX_HOST"):
        logger.error("PROXMOX_HOST is not set")
        logger.error("Set it in the environment; see the administrator guide")
        sys.exit(1)

    host = args.host if args.host is not None else os.getenv("REDFISH_HOST", "")
    port = args.port if args.port is not None else int(os.getenv("REDFISH_PORT", str(DEFAULT_PORT)))

    # TLS is used when both a certificate and a key are configured.
    use_tls = bool(os.getenv("SSL_CERT_FILE")) and bool(os.getenv("SSL_KEY_FILE"))

    try:
        logger.info("Starting Proxmox Redfish Daemon...")
        logger.info("Proxmox Host: %s", os.getenv("PROXMOX_HOST"))
        logger.info("Listening on %s:%s", host or "0.0.0.0", port)

        if use_tls:
            logger.info("Starting Redfish server with SSL...")
            run_server_ssl(port, host)
        else:
            logger.info("Starting Redfish server without SSL...")
            run_server(port, host)

    except KeyboardInterrupt:
        logger.info("Shutting down Proxmox Redfish Daemon...")

    except Exception as e:
        logger.error(f"Failed to start daemon: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
