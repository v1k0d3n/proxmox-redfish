#!/usr/bin/env python3
"""
Proxmox Redfish Daemon

A Redfish API daemon for managing Proxmox VMs, providing a standardized interface
for VM operations through the Redfish protocol.
"""

import argparse
import json
import logging
import os
import sys

from .config.logging_config import logger, setup_logging
from .server.http_server import run_server
from .server.ssl_server import run_server_ssl


def main() -> None:
    """Main entry point for the proxmox-redfish daemon."""
    parser = argparse.ArgumentParser(description="Proxmox Redfish Daemon - Redfish API for Proxmox VMs")
    parser.add_argument("--config", help="Path to configuration file (JSON format)")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument("--port", type=int, help="Port to run the server on (overrides config)")
    parser.add_argument("--host", help="Host to bind to (default: 0.0.0.0)")

    args = parser.parse_args()

    # Setup logging
    setup_logging()
    logging.basicConfig(
        level=getattr(logging, args.log_level), format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Load configuration
    config = {}

    # Load from config file if specified
    if args.config:
        try:
            with open(args.config, "r") as f:
                config = json.load(f)
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Failed to load config file {args.config}: {e}")
            sys.exit(1)

    # Override with environment variables
    if os.getenv("PROXMOX_HOST"):
        config.setdefault("proxmox", {})["host"] = os.getenv("PROXMOX_HOST")
    if os.getenv("PROXMOX_USER"):
        config.setdefault("proxmox", {})["user"] = os.getenv("PROXMOX_USER")
    if os.getenv("PROXMOX_PASSWORD"):
        config.setdefault("proxmox", {})["password"] = os.getenv("PROXMOX_PASSWORD")
    if os.getenv("REDFISH_PORT"):
        port_value = os.getenv("REDFISH_PORT")
        if port_value:
            config.setdefault("redfish", {})["port"] = int(port_value)
    if os.getenv("SSL_CERT_FILE"):
        config.setdefault("redfish", {})["ssl_cert"] = os.getenv("SSL_CERT_FILE")
    if os.getenv("SSL_KEY_FILE"):
        config.setdefault("redfish", {})["ssl_key"] = os.getenv("SSL_KEY_FILE")
    if os.getenv("LOG_LEVEL"):
        config.setdefault("logging", {})["level"] = os.getenv("LOG_LEVEL")

    # Override with command line arguments
    if args.port:
        config.setdefault("redfish", {})["port"] = args.port
    if args.host:
        config.setdefault("redfish", {})["host"] = args.host

    # Set defaults
    config.setdefault("redfish", {}).setdefault("port", 8443)
    config.setdefault("redfish", {}).setdefault("host", "0.0.0.0")
    config.setdefault("logging", {}).setdefault("level", "INFO")

    # Validate required configuration
    proxmox_config = config.get("proxmox", {})
    if not all(key in proxmox_config for key in ["host", "user", "password"]):
        logger.error("Missing required Proxmox configuration: host, user, password")
        logger.error("Set via environment variables or config file")
        sys.exit(1)

    # Start the daemon
    try:
        logger.info("Starting Proxmox Redfish Daemon...")
        logger.info(f"Proxmox Host: {proxmox_config['host']}")
        logger.info(f"Redfish Port: {config['redfish']['port']}")

        # Check if SSL certificates are configured
        ssl_cert = config.get("redfish", {}).get("ssl_cert")
        ssl_key = config.get("redfish", {}).get("ssl_key")

        if ssl_cert and ssl_key:
            # Start SSL server
            logger.info("Starting Redfish server with SSL...")
            run_server_ssl(config["redfish"]["port"])
        else:
            # Start regular HTTP server
            logger.info("Starting Redfish server without SSL...")
            run_server(config["redfish"]["port"])

    except KeyboardInterrupt:
        logger.info("Shutting down Proxmox Redfish Daemon...")

    except Exception as e:
        logger.error(f"Failed to start daemon: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
